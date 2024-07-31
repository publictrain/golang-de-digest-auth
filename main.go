package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"

	"github.com/publictrain/golang-de-digest-auth/auth"
)

func main() {
	// ユーザーのHA1ハッシュ値（username:realm:passwordをSHA-256でハッシュ化したもの）
	usersHA1 := map[string]string{
		"testuser": fmt.Sprintf("%x", sha256.Sum256([]byte("testuser:MyRealm:testpassword"))),
	}

	authHandler := auth.NewAuth(http.HandlerFunc(protectedHandler), "MyRealm", usersHA1)

	http.Handle("/", authHandler)
	fmt.Println("Server started at :8080")
	http.ListenAndServe(":8080", nil)
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, "You have accessed a protected resource!")
}
