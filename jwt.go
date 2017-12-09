package main

import (
	"context"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"strings"
	"time"
)

type UserToken struct {
	Id   string `json:"id"`
	Role string `json:"role"`
}

type JWTClaims struct {
	User UserToken `json:"user"`
	jwt.StandardClaims
}

type JWTMiddleware struct {
	SigningAlgorithm string
	SigningKey       interface{}
	ClaimsField      string
	TokenField       string
}

func NewClaims(user UserToken, expiry time.Duration) *JWTClaims {
	now := time.Now()
	return &JWTClaims{
		user,
		jwt.StandardClaims{
			ExpiresAt: now.Add(expiry).Unix(),
			IssuedAt:  now.Unix(),
			NotBefore: now.Unix(),
		},
	}
}

func (middleware *JWTMiddleware) Refresh(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value(middleware.ClaimsField).(*JWTClaims)
		if claims == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		token, err := jwt.NewWithClaims(jwt.GetSigningMethod(middleware.SigningAlgorithm),
			claims).SignedString(middleware.SigningKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), middleware.TokenField, token)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func (middleware *JWTMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signedToken, err := middleware.getSignedTokenFromHeader(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		token, err := middleware.parseToken(signedToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), middleware.ClaimsField, token.Claims)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func (middleware *JWTMiddleware) getSignedTokenFromHeader(r *http.Request) (string, error) {
	tokens, ok := r.Header["Authorization"]
	// if there is no token
	if !ok || len(tokens) == 0 {
		return "", fmt.Errorf("Empty authorization header.")
	}

	signedToken := strings.TrimPrefix(tokens[0], "Bearer ")
	if signedToken == "" {
		return "", fmt.Errorf("Empty token.")
	}

	return signedToken, nil
}

func (middleware *JWTMiddleware) parseToken(signedToken string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(signedToken, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != middleware.SigningAlgorithm {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return middleware.SigningKey, nil
	})

	if err != nil {
		return nil, err
	}

	if token == nil {
		return nil, fmt.Errorf("Token was nil.")
	}

	if !token.Valid {
		return nil, fmt.Errorf("Token is invalid.")
	}

	return token, nil
}
