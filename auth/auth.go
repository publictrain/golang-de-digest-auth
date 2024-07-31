package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Auth struct {
	Handler    http.Handler
	Realm      string
	UsersHA1   map[string]string
	Nonces     map[string]time.Time
	UsedNonces map[string]map[string]bool // Nonce + nc ペアを管理
}

func NewAuth(handler http.Handler, realm string, usersHA1 map[string]string) *Auth {
	auth := &Auth{
		Handler:    handler,
		Realm:      realm,
		UsersHA1:   usersHA1,
		Nonces:     make(map[string]time.Time),
		UsedNonces: make(map[string]map[string]bool),
	}

	// Nonceの期限切れを定期的にクリーンアップする
	go func() {
		for {
			time.Sleep(time.Minute * 1)
			auth.cleanupNonces()
		}
	}()

	return auth
}

func (a *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		a.requireAuth(w, r)
		return
	}

	if strings.HasPrefix(authHeader, "Digest ") {
		a.handleDigestAuth(w, r, authHeader)
	} else {
		a.requireAuth(w, r)
	}
}

func (a *Auth) requireAuth(w http.ResponseWriter, r *http.Request) {
	nonce, err := generateNonce()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	a.Nonces[nonce] = time.Now()
	authHeader := fmt.Sprintf(`Digest realm="%s", nonce="%s", algorithm=SHA-256, qop="auth"`, a.Realm, nonce)
	w.Header().Set("WWW-Authenticate", authHeader)
	w.WriteHeader(http.StatusUnauthorized)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintln(w, `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Unauthorized</title>
</head><body>
<h1>Unauthorized</h1>
<p>This server could not verify that you
are authorized to access the document
requested. Either you supplied the wrong
credentials (e.g., bad password), or your
browser doesn't understand how to supply
the credentials required.</p>
</body></html>`)
}

func (a *Auth) handleDigestAuth(w http.ResponseWriter, r *http.Request, authHeader string) {
	authDetails := parseDigestAuth(authHeader)
	if !a.validateDigestAuth(authDetails, r.Method) {
		a.requireAuth(w, r)
		return
	}

	a.Handler.ServeHTTP(w, r)
}

func parseDigestAuth(authHeader string) map[string]string {
	authDetails := make(map[string]string)
	keyVals := strings.Split(authHeader[7:], ", ")
	for _, keyVal := range keyVals {
		parts := strings.SplitN(keyVal, "=", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(parts[1], `"`)
		authDetails[key] = value
	}
	return authDetails
}

func (a *Auth) validateDigestAuth(authDetails map[string]string, method string) bool {
	username := authDetails["username"]
	expectedHA1, userExists := a.UsersHA1[username]
	if !userExists {
		return false
	}

	if authDetails["qop"] != "auth" {
		return false
	}

	ha2 := fmt.Sprintf("%x", sha256.Sum256([]byte(method+":"+authDetails["uri"])))
	response := fmt.Sprintf("%x", sha256.Sum256([]byte(expectedHA1+":"+authDetails["nonce"]+":"+authDetails["nc"]+":"+authDetails["cnonce"]+":"+authDetails["qop"]+":"+ha2)))

	if response != authDetails["response"] {
		return false
	}

	// Nonce + nc ペアを確認
	if _, ok := a.UsedNonces[authDetails["nonce"]]; !ok {
		a.UsedNonces[authDetails["nonce"]] = make(map[string]bool)
	}
	if a.UsedNonces[authDetails["nonce"]][authDetails["nc"]] {
		return false // 同じnonce + ncのペアは再利用不可
	}
	a.UsedNonces[authDetails["nonce"]][authDetails["nc"]] = true

	// Check if nonce is still valid
	if nonceTime, ok := a.Nonces[authDetails["nonce"]]; ok {
		if time.Since(nonceTime) > time.Minute*5 {
			delete(a.Nonces, authDetails["nonce"])
			return false
		}
	} else {
		return false
	}

	return true
}

func generateNonce() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func (a *Auth) cleanupNonces() {
	for nonce, timestamp := range a.Nonces {
		if time.Since(timestamp) > time.Minute*5 {
			delete(a.Nonces, nonce)
			delete(a.UsedNonces, nonce)
		}
	}
}
