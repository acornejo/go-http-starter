package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func RandId() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func HelloWorld(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*JWTClaims)
	if claims != nil {
		if claims.User.Role == "unauthenticated" {
			w.Write([]byte("User is unauthenticated!\n"))
		}
		err := json.NewEncoder(w).Encode(claims.User)
		if err != nil {
			w.Write([]byte(err.Error()))
		}
	} else {
		w.Write([]byte("no claims"))
	}
}

func SendJSONToken(w http.ResponseWriter, r *http.Request) {
	token := r.Context().Value("token")
	w.Header().Set("Content-Type", "application/json")
	tokenMap := make(map[string]string)
	tokenMap["token"] = fmt.Sprintf("%v", token)
	err := json.NewEncoder(w).Encode(tokenMap)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func Anonymous(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := NewClaims(UserToken{
			RandId(),
			"unauthenticated",
		}, 1*time.Hour)
		ctx := context.WithValue(r.Context(), "claims", claims)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func Login(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Look at request params and determine if login is valid
		// or not.
		claims := NewClaims(UserToken{
			"1234",
			"authenticated",
		}, 1*time.Hour)
		ctx := context.WithValue(r.Context(), "claims", claims)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func main() {
	jwt := &JWTMiddleware{
		SigningAlgorithm: "HS256",
		SigningKey:       []byte("secret"),
		ClaimsField:      "claims",
		TokenField:       "token",
	}
	http.Handle("/anon", Anonymous(jwt.Refresh(http.HandlerFunc(SendJSONToken))))
	http.Handle("/login", Login(jwt.Refresh(http.HandlerFunc(SendJSONToken))))
	http.Handle("/", jwt.Authenticate(http.HandlerFunc(HelloWorld)))

	server := &http.Server{}
	server.Serve(GetSecureListener("server.hastyrobot.com", "acornejo@gmail.com", "certs"))
}
