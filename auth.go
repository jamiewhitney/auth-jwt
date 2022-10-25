package auth

import (
	"errors"
	"fmt"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"log"
	"net/http"
	"strings"
)

var (
	errInvalidScope = errors.New("invalid scope").Error()
)

type Authorizer struct {
	Audience string
	Scope    string
	Issuer   string
	Jwks     *keyfunc.JWKS
}

type MyCustomClaims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

func NewAuthorizer(scope string, audience string, issuer string, jwksURL string) *Authorizer {
	jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{})
	if err != nil {
		log.Fatalf("Failed to get the JWKS from the given URL. Error: %s", err)
	}

	return &Authorizer{
		Audience: audience,
		Scope:    scope,
		Issuer:   issuer,
		Jwks:     jwks,
	}
}

func (a *Authorizer) EnsureValidToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		accessToken := strings.TrimPrefix(authorization, "Bearer ")

		token, claims, err := a.ParseToken(accessToken)
		if err != nil {
			fmt.Println(err)
		}

		if !token.Valid {
			http.Error(w, jwt.ErrTokenInvalidClaims.Error(), http.StatusUnauthorized)
		}

		if err := claims.Valid(); err != nil {
			http.Error(w, jwt.ErrTokenInvalidClaims.Error(), http.StatusUnauthorized)
		}

		if !claims.HasScope(a.Scope) {
			http.Error(w, errInvalidScope, http.StatusUnauthorized)
		}

		if claims.Issuer != a.Issuer {
			http.Error(w, jwt.ErrTokenInvalidIssuer.Error(), http.StatusUnauthorized)
		}

		for _, i := range claims.Audience {
			if i != a.Audience {
				http.Error(w, jwt.ErrTokenInvalidAudience.Error(), http.StatusUnauthorized)
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (a *Authorizer) ParseToken(authorization string) (*jwt.Token, *MyCustomClaims, error) {
	if len(authorization) < 1 {
		return nil, nil, nil
	}

	accessToken := strings.TrimPrefix(authorization, "Bearer ")

	claimsStruct := MyCustomClaims{}
	token, err := jwt.ParseWithClaims(accessToken, &claimsStruct, a.Jwks.Keyfunc)
	if err != nil {
		return nil, nil, err
	}
	return token, &claimsStruct, nil
}

func (c MyCustomClaims) HasScope(expectedScope string) bool {
	result := strings.Split(c.Scope, " ")
	for i := range result {
		if result[i] == expectedScope {
			return true
		}
	}

	return false
}
