// Code generated by goa v3.0.6, DO NOT EDIT.
//
// user endpoints
//
// Command:
// $ goa gen github.com/anshap1719/go-authentication/design

package user

import (
	"context"

	goa "goa.design/goa/v3/pkg"
	"goa.design/goa/v3/security"
)

// Endpoints wraps the "user" service endpoints.
type Endpoints struct {
	GetAuths          goa.Endpoint
	Deactivate        goa.Endpoint
	GetUser           goa.Endpoint
	ValidateEmail     goa.Endpoint
	UpdateUser        goa.Endpoint
	ResendVerifyEmail goa.Endpoint
	UpdatePhone       goa.Endpoint
	ResendOtp         goa.Endpoint
	VerifyPhone       goa.Endpoint
}

// NewEndpoints wraps the methods of the "user" service with endpoints.
func NewEndpoints(s Service) *Endpoints {
	// Casting service to Auther interface
	a := s.(Auther)
	return &Endpoints{
		GetAuths:          NewGetAuthsEndpoint(s, a.APIKeyAuth),
		Deactivate:        NewDeactivateEndpoint(s, a.JWTAuth, a.APIKeyAuth),
		GetUser:           NewGetUserEndpoint(s, a.JWTAuth, a.APIKeyAuth),
		ValidateEmail:     NewValidateEmailEndpoint(s, a.APIKeyAuth),
		UpdateUser:        NewUpdateUserEndpoint(s, a.JWTAuth, a.APIKeyAuth),
		ResendVerifyEmail: NewResendVerifyEmailEndpoint(s, a.APIKeyAuth),
		UpdatePhone:       NewUpdatePhoneEndpoint(s, a.JWTAuth, a.APIKeyAuth),
		ResendOtp:         NewResendOtpEndpoint(s, a.JWTAuth, a.APIKeyAuth),
		VerifyPhone:       NewVerifyPhoneEndpoint(s, a.JWTAuth, a.APIKeyAuth),
	}
}

// Use applies the given middleware to all the "user" service endpoints.
func (e *Endpoints) Use(m func(goa.Endpoint) goa.Endpoint) {
	e.GetAuths = m(e.GetAuths)
	e.Deactivate = m(e.Deactivate)
	e.GetUser = m(e.GetUser)
	e.ValidateEmail = m(e.ValidateEmail)
	e.UpdateUser = m(e.UpdateUser)
	e.ResendVerifyEmail = m(e.ResendVerifyEmail)
	e.UpdatePhone = m(e.UpdatePhone)
	e.ResendOtp = m(e.ResendOtp)
	e.VerifyPhone = m(e.VerifyPhone)
}

// NewGetAuthsEndpoint returns an endpoint function that calls the method
// "getAuths" of service "user".
func NewGetAuthsEndpoint(s Service, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*GetAuthsPayload)
		var err error
		sc := security.APIKeyScheme{
			Name:           "api_key",
			Scopes:         []string{},
			RequiredScopes: []string{},
		}
		var key string
		if p.APIKey != nil {
			key = *p.APIKey
		}
		ctx, err = authAPIKeyFn(ctx, key, &sc)
		if err != nil {
			return nil, err
		}
		res, err := s.GetAuths(ctx, p)
		if err != nil {
			return nil, err
		}
		vres := NewViewedAuthStatusMedia(res, "default")
		return vres, nil
	}
}

// NewDeactivateEndpoint returns an endpoint function that calls the method
// "deactivate" of service "user".
func NewDeactivateEndpoint(s Service, authJWTFn security.AuthJWTFunc, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*DeactivatePayload)
		var err error
		sc := security.JWTScheme{
			Name:           "jwt",
			Scopes:         []string{},
			RequiredScopes: []string{},
		}
		var token string
		if p.Authorization != nil {
			token = *p.Authorization
		}
		ctx, err = authJWTFn(ctx, token, &sc)
		if err == nil {
			sc := security.APIKeyScheme{
				Name:           "api_key",
				Scopes:         []string{},
				RequiredScopes: []string{},
			}
			var key string
			if p.APIKey != nil {
				key = *p.APIKey
			}
			ctx, err = authAPIKeyFn(ctx, key, &sc)
		}
		if err != nil {
			return nil, err
		}
		return nil, s.Deactivate(ctx, p)
	}
}

// NewGetUserEndpoint returns an endpoint function that calls the method
// "getUser" of service "user".
func NewGetUserEndpoint(s Service, authJWTFn security.AuthJWTFunc, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*GetUserPayload)
		var err error
		sc := security.JWTScheme{
			Name:           "jwt",
			Scopes:         []string{},
			RequiredScopes: []string{},
		}
		var token string
		if p.Authorization != nil {
			token = *p.Authorization
		}
		ctx, err = authJWTFn(ctx, token, &sc)
		if err == nil {
			sc := security.APIKeyScheme{
				Name:           "api_key",
				Scopes:         []string{},
				RequiredScopes: []string{},
			}
			var key string
			if p.APIKey != nil {
				key = *p.APIKey
			}
			ctx, err = authAPIKeyFn(ctx, key, &sc)
		}
		if err != nil {
			return nil, err
		}
		res, err := s.GetUser(ctx, p)
		if err != nil {
			return nil, err
		}
		vres := NewViewedUserMedia(res, "default")
		return vres, nil
	}
}

// NewValidateEmailEndpoint returns an endpoint function that calls the method
// "validate-email" of service "user".
func NewValidateEmailEndpoint(s Service, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*ValidateEmailPayload)
		var err error
		sc := security.APIKeyScheme{
			Name:           "api_key",
			Scopes:         []string{},
			RequiredScopes: []string{},
		}
		var key string
		if p.APIKey != nil {
			key = *p.APIKey
		}
		ctx, err = authAPIKeyFn(ctx, key, &sc)
		if err != nil {
			return nil, err
		}
		return nil, s.ValidateEmail(ctx, p)
	}
}

// NewUpdateUserEndpoint returns an endpoint function that calls the method
// "update-user" of service "user".
func NewUpdateUserEndpoint(s Service, authJWTFn security.AuthJWTFunc, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*UserUpdateParams)
		var err error
		sc := security.JWTScheme{
			Name:           "jwt",
			Scopes:         []string{},
			RequiredScopes: []string{},
		}
		var token string
		if p.Authorization != nil {
			token = *p.Authorization
		}
		ctx, err = authJWTFn(ctx, token, &sc)
		if err == nil {
			sc := security.APIKeyScheme{
				Name:           "api_key",
				Scopes:         []string{},
				RequiredScopes: []string{},
			}
			var key string
			if p.APIKey != nil {
				key = *p.APIKey
			}
			ctx, err = authAPIKeyFn(ctx, key, &sc)
		}
		if err != nil {
			return nil, err
		}
		res, err := s.UpdateUser(ctx, p)
		if err != nil {
			return nil, err
		}
		vres := NewViewedUserMedia(res, "default")
		return vres, nil
	}
}

// NewResendVerifyEmailEndpoint returns an endpoint function that calls the
// method "resend-verify-email" of service "user".
func NewResendVerifyEmailEndpoint(s Service, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*ResendVerifyEmailPayload)
		var err error
		sc := security.APIKeyScheme{
			Name:           "api_key",
			Scopes:         []string{},
			RequiredScopes: []string{},
		}
		var key string
		if p.APIKey != nil {
			key = *p.APIKey
		}
		ctx, err = authAPIKeyFn(ctx, key, &sc)
		if err != nil {
			return nil, err
		}
		return nil, s.ResendVerifyEmail(ctx, p)
	}
}

// NewUpdatePhoneEndpoint returns an endpoint function that calls the method
// "update-phone" of service "user".
func NewUpdatePhoneEndpoint(s Service, authJWTFn security.AuthJWTFunc, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*UpdatePhonePayload)
		var err error
		sc := security.JWTScheme{
			Name:           "jwt",
			Scopes:         []string{},
			RequiredScopes: []string{},
		}
		var token string
		if p.Authorization != nil {
			token = *p.Authorization
		}
		ctx, err = authJWTFn(ctx, token, &sc)
		if err == nil {
			sc := security.APIKeyScheme{
				Name:           "api_key",
				Scopes:         []string{},
				RequiredScopes: []string{},
			}
			var key string
			if p.APIKey != nil {
				key = *p.APIKey
			}
			ctx, err = authAPIKeyFn(ctx, key, &sc)
		}
		if err != nil {
			return nil, err
		}
		return nil, s.UpdatePhone(ctx, p)
	}
}

// NewResendOtpEndpoint returns an endpoint function that calls the method
// "resend-otp" of service "user".
func NewResendOtpEndpoint(s Service, authJWTFn security.AuthJWTFunc, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*ResendOtpPayload)
		var err error
		sc := security.JWTScheme{
			Name:           "jwt",
			Scopes:         []string{},
			RequiredScopes: []string{},
		}
		var token string
		if p.Authorization != nil {
			token = *p.Authorization
		}
		ctx, err = authJWTFn(ctx, token, &sc)
		if err == nil {
			sc := security.APIKeyScheme{
				Name:           "api_key",
				Scopes:         []string{},
				RequiredScopes: []string{},
			}
			var key string
			if p.APIKey != nil {
				key = *p.APIKey
			}
			ctx, err = authAPIKeyFn(ctx, key, &sc)
		}
		if err != nil {
			return nil, err
		}
		return nil, s.ResendOtp(ctx, p)
	}
}

// NewVerifyPhoneEndpoint returns an endpoint function that calls the method
// "verify-phone" of service "user".
func NewVerifyPhoneEndpoint(s Service, authJWTFn security.AuthJWTFunc, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*VerifyPhonePayload)
		var err error
		sc := security.JWTScheme{
			Name:           "jwt",
			Scopes:         []string{},
			RequiredScopes: []string{},
		}
		var token string
		if p.Authorization != nil {
			token = *p.Authorization
		}
		ctx, err = authJWTFn(ctx, token, &sc)
		if err == nil {
			sc := security.APIKeyScheme{
				Name:           "api_key",
				Scopes:         []string{},
				RequiredScopes: []string{},
			}
			var key string
			if p.APIKey != nil {
				key = *p.APIKey
			}
			ctx, err = authAPIKeyFn(ctx, key, &sc)
		}
		if err != nil {
			return nil, err
		}
		return nil, s.VerifyPhone(ctx, p)
	}
}
