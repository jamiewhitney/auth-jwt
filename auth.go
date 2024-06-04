package auth

import (
	"context"
	"fmt"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"log"
	"net/http"
	"strings"
)

type Authorizer struct {
	Audience string
	Issuer   string
	Jwks     *keyfunc.JWKS
	insecure bool
}

type MyCustomClaims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

func NewAuthorizer(audience string, issuer string, jwksDomain string, ops ...OptsFunc) *Authorizer {
	if jwksDomain == "" {
		return &Authorizer{
			Audience: audience,
			Issuer:   issuer,
			Jwks:     nil,
		}
	}

	o := defaultOpts()
	for _, fn := range ops {
		fn(&o)
	}

	jwks, err := keyfunc.Get(fmt.Sprintf("https://%s/.well-known/jwks.json", jwksDomain), keyfunc.Options{})
	if err != nil {
		log.Fatalf("Failed to get the JWKS from the given URL. Error: %s", err)
	}

	if o.insecure {
		return &Authorizer{
			Audience: "",
			Issuer:   "",
			Jwks:     nil,
			insecure: true,
		}
	}
	return &Authorizer{
		Audience: audience,
		Issuer:   issuer,
		Jwks:     jwks,
	}
}

type OptsFunc func(*Opts)
type Opts struct {
	insecure bool
}

func defaultOpts() Opts {
	return Opts{
		insecure: false,
	}
}

func WithInsecure(n bool) OptsFunc {
	return func(opts *Opts) {
		opts.insecure = n
	}
}

func (a *Authorizer) EnsureValidToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		if authorization == "" {
			http.Error(w, "Missing Authorization header", http.StatusBadRequest)
			return
		}
		accessToken := strings.TrimPrefix(authorization, "Bearer ")

		_, claims, err := a.parseToken(accessToken)
		if err != nil {
			log.Println(err)
			http.Error(w, "failed to parse token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *Authorizer) parseToken(authorization string) (*jwt.Token, *MyCustomClaims, error) {
	if len(authorization) < 1 {
		return nil, nil, nil
	}

	accessToken := strings.TrimPrefix(authorization, "Bearer ")

	claimsStruct := MyCustomClaims{}

	if !a.insecure {
		token, _, err := jwt.NewParser().ParseUnverified(accessToken, &claimsStruct)
		if err != nil {
			return nil, nil, err
		}
		return token, &claimsStruct, nil
	} else {
		token, err := jwt.ParseWithClaims(accessToken, &claimsStruct, a.Jwks.Keyfunc)
		if err != nil {
			return nil, nil, err
		}
		return token, &claimsStruct, nil
	}
}

func (a *Authorizer) parseTokenUnverified(authorization string) (*jwt.Token, *MyCustomClaims, error) {
	if len(authorization) < 1 {
		return nil, nil, nil
	}

	accessToken := strings.TrimPrefix(authorization, "Bearer ")

	claimsStruct := MyCustomClaims{}
	token, _, err := jwt.NewParser().ParseUnverified(accessToken, &claimsStruct)
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

func (a *Authorizer) AuthorizeScope(next http.HandlerFunc, requiredScope []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value("claims").(*MyCustomClaims)
		if claims == nil {
			http.Error(w, "no claims provided", http.StatusBadRequest)
			return
		}

		hasScope := false
		for _, scope := range requiredScope {
			if claims.HasScope(scope) {
				hasScope = true
				break
			}
		}

		if !hasScope {
			http.Error(w, fmt.Sprintf("%s is unauthorized to access", claims.Subject), http.StatusUnauthorized)
			return
		}
		// Call the next handler in the chain
		next.ServeHTTP(w, r)
	}
}
