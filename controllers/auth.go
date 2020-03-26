package controllers

import (
	"context"
	"errors"
	"fmt"
	"github.com/anshap1719/authentication/controllers/gen/facebook"
	"github.com/anshap1719/authentication/controllers/gen/google"
	"github.com/anshap1719/authentication/controllers/gen/instagram"
	"github.com/anshap1719/authentication/controllers/gen/linkedin"
	passwordauth "github.com/anshap1719/authentication/controllers/gen/password_auth"
	"github.com/anshap1719/authentication/controllers/gen/session"
	"github.com/anshap1719/authentication/controllers/gen/twitter"
	"github.com/anshap1719/authentication/controllers/gen/user"
	"github.com/anshap1719/authentication/utils/auth"
	goa "goa.design/goa/v3/pkg"

	"goa.design/goa/v3/security"
)

var (
	// ErrUnauthorized is the error returned by Login when the request credentials
	// are invalid.
	ErrUnauthorized error = errors.New("invalid username and password combination")

	ErrNoKey error = errors.New("api key missing")

	// Key is the key used in JWT authentication
	Key    = []byte("secret")
	APIKey = "qi8s1UgnmfAIAHRTlpwgGwnoHHO6kZEi"
)

// JWTAuth implements the authorization logic for service "facebook" for the
// "jwt" security scheme.
func (s *FacebookService) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	jwtSec, err := auth.NewJWTSecurity()
	if err != nil {
		return ctx, facebook.MakeInternalServerError(errors.New("unable to verify token"))
	}

	if ok := jwtSec.IsAuthenticated(token); !ok {
		return ctx, facebook.MakeUnauthorized(errors.New("invalid token"))
	}

	return ctx, nil
}

// JWTAuth implements the authorization logic for service "google" for the
// "jwt" security scheme.
func (s *GoogleService) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	jwtSec, err := auth.NewJWTSecurity()
	if err != nil {
		return ctx, google.MakeInternalServerError(errors.New("unable to verify token"))
	}

	if ok := jwtSec.IsAuthenticated(token); !ok {
		return ctx, google.MakeUnauthorized(errors.New("invalid token"))
	}

	return ctx, nil
}

// JWTAuth implements the authorization logic for service "instagram" for the
// "jwt" security scheme.
func (s *InstagramService) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	jwtSec, err := auth.NewJWTSecurity()
	if err != nil {
		return ctx, instagram.MakeInternalServerError(errors.New("unable to verify token"))
	}

	if ok := jwtSec.IsAuthenticated(token); !ok {
		return ctx, instagram.MakeUnauthorized(errors.New("invalid token"))
	}

	return ctx, nil
}

// JWTAuth implements the authorization logic for service "linkedin" for the
// "jwt" security scheme.
func (s *LinkedinService) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	jwtSec, err := auth.NewJWTSecurity()
	if err != nil {
		return ctx, linkedin.MakeInternalServerError(errors.New("unable to verify token"))
	}

	if ok := jwtSec.IsAuthenticated(token); !ok {
		return ctx, linkedin.MakeUnauthorized(errors.New("invalid token"))
	}

	return ctx, nil
}

// JWTAuth implements the authorization logic for service "password-auth" for
// the "jwt" security scheme.
func (s *PasswordAuthService) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	jwtSec, err := auth.NewJWTSecurity()
	if err != nil {
		return ctx, passwordauth.MakeInternalServerError(errors.New("unable to verify token"))
	}

	if ok := jwtSec.IsAuthenticated(token); !ok {
		return ctx, passwordauth.MakeUnauthorized(errors.New("invalid token"))
	}

	return ctx, nil
}

// JWTAuth implements the authorization logic for service "session" for the
// "jwt" security scheme.
func (s *SessionService) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	jwtSec, err := auth.NewJWTSecurity()
	if err != nil {
		return ctx, session.MakeInternalServerError(errors.New("unable to verify token"))
	}

	if ok := jwtSec.IsAuthenticated(token); !ok {
		return ctx, session.MakeUnauthorized(errors.New("invalid token"))
	}

	return ctx, nil
}

// JWTAuth implements the authorization logic for service "twitter" for the
// "jwt" security scheme.
func (s *TwitterService) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	jwtSec, err := auth.NewJWTSecurity()
	if err != nil {
		return ctx, twitter.MakeInternalServerError(errors.New("unable to verify token"))
	}

	if ok := jwtSec.IsAuthenticated(token); !ok {
		return ctx, twitter.MakeUnauthorized(errors.New("invalid token"))
	}

	return ctx, nil
}

// JWTAuth implements the authorization logic for service "user" for the "jwt"
// security scheme.
func (s *UsersService) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	jwtSec, err := auth.NewJWTSecurity()
	if err != nil {
		return ctx, user.MakeInternalServerError(errors.New("unable to verify token"))
	}

	if ok := jwtSec.IsAuthenticated(token); !ok {
		return ctx, user.MakeUnauthorized(errors.New("invalid token"))
	}

	return ctx, nil
}

func checkAPIKey(MakeUnauthorized func(err error) *goa.ServiceError, key string) error {
	if key == "" {
		fmt.Println("here 3")
		return MakeUnauthorized(ErrNoKey)
	} else if APIKey == key {
		return nil
	} else {
		return MakeUnauthorized(ErrNoKey)
	}

}

// APIKeyAuth implements the authorization logic for service "facebook" for the
// "api_key" security scheme.
func (s *FacebookService) APIKeyAuth(ctx context.Context, key string, scheme *security.APIKeyScheme) (context.Context, error) {
	return ctx, checkAPIKey(facebook.MakeUnauthorized, key)
}

// APIKeyAuth implements the authorization logic for service "google" for the
// "api_key" security scheme.
func (s *GoogleService) APIKeyAuth(ctx context.Context, key string, scheme *security.APIKeyScheme) (context.Context, error) {
	return ctx, checkAPIKey(google.MakeUnauthorized, key)
}

// APIKeyAuth implements the authorization logic for service "instagram" for
// the "api_key" security scheme.
func (s *InstagramService) APIKeyAuth(ctx context.Context, key string, scheme *security.APIKeyScheme) (context.Context, error) {
	return ctx, checkAPIKey(instagram.MakeUnauthorized, key)
}

// APIKeyAuth implements the authorization logic for service "linkedin" for the
// "api_key" security scheme.
func (s *LinkedinService) APIKeyAuth(ctx context.Context, key string, scheme *security.APIKeyScheme) (context.Context, error) {
	return ctx, checkAPIKey(linkedin.MakeUnauthorized, key)
}

// APIKeyAuth implements the authorization logic for service "password-auth"
// for the "api_key" security scheme.
func (s *PasswordAuthService) APIKeyAuth(ctx context.Context, key string, scheme *security.APIKeyScheme) (context.Context, error) {
	return ctx, checkAPIKey(passwordauth.MakeUnauthorized, key)
}

// APIKeyAuth implements the authorization logic for service "session" for the
// "api_key" security scheme.
func (s *SessionService) APIKeyAuth(ctx context.Context, key string, scheme *security.APIKeyScheme) (context.Context, error) {
	return ctx, checkAPIKey(session.MakeUnauthorized, key)
}

// APIKeyAuth implements the authorization logic for service "twitter" for the
// "api_key" security scheme.
func (s *TwitterService) APIKeyAuth(ctx context.Context, key string, scheme *security.APIKeyScheme) (context.Context, error) {
	return ctx, checkAPIKey(twitter.MakeUnauthorized, key)
}

// APIKeyAuth implements the authorization logic for service "user" for the
// "api_key" security scheme.
func (s *UsersService) APIKeyAuth(ctx context.Context, key string, scheme *security.APIKeyScheme) (context.Context, error) {
	return ctx, checkAPIKey(user.MakeUnauthorized, key)
}
