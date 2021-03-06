// Code generated by goa v3.0.6, DO NOT EDIT.
//
// password-auth endpoints
//
// Command:
// $ goa gen github.com/anshap1719/authentication/design

package passwordauth

import (
	"context"

	goa "goa.design/goa/v3/pkg"
	"goa.design/goa/v3/security"
)

// Endpoints wraps the "password-auth" service endpoints.
type Endpoints struct {
	Register            goa.Endpoint
	Login               goa.Endpoint
	Remove              goa.Endpoint
	ChangePassword      goa.Endpoint
	Reset               goa.Endpoint
	ConfirmReset        goa.Endpoint
	CheckEmailAvailable goa.Endpoint
	CheckPhoneAvailable goa.Endpoint
}

// NewEndpoints wraps the methods of the "password-auth" service with endpoints.
func NewEndpoints(s Service) *Endpoints {
	// Casting service to Auther interface
	a := s.(Auther)
	return &Endpoints{
		Register:            NewRegisterEndpoint(s, a.APIKeyAuth),
		Login:               NewLoginEndpoint(s, a.APIKeyAuth),
		Remove:              NewRemoveEndpoint(s, a.JWTAuth, a.APIKeyAuth),
		ChangePassword:      NewChangePasswordEndpoint(s, a.JWTAuth, a.APIKeyAuth),
		Reset:               NewResetEndpoint(s, a.APIKeyAuth),
		ConfirmReset:        NewConfirmResetEndpoint(s, a.APIKeyAuth),
		CheckEmailAvailable: NewCheckEmailAvailableEndpoint(s, a.APIKeyAuth),
		CheckPhoneAvailable: NewCheckPhoneAvailableEndpoint(s, a.APIKeyAuth),
	}
}

// Use applies the given middleware to all the "password-auth" service
// endpoints.
func (e *Endpoints) Use(m func(goa.Endpoint) goa.Endpoint) {
	e.Register = m(e.Register)
	e.Login = m(e.Login)
	e.Remove = m(e.Remove)
	e.ChangePassword = m(e.ChangePassword)
	e.Reset = m(e.Reset)
	e.ConfirmReset = m(e.ConfirmReset)
	e.CheckEmailAvailable = m(e.CheckEmailAvailable)
	e.CheckPhoneAvailable = m(e.CheckPhoneAvailable)
}

// NewRegisterEndpoint returns an endpoint function that calls the method
// "register" of service "password-auth".
func NewRegisterEndpoint(s Service, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*RegisterParams)
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
		res, err := s.Register(ctx, p)
		if err != nil {
			return nil, err
		}
		vres := NewViewedUserMedia(res, "default")
		return vres, nil
	}
}

// NewLoginEndpoint returns an endpoint function that calls the method "login"
// of service "password-auth".
func NewLoginEndpoint(s Service, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*LoginParams)
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
		res, err := s.Login(ctx, p)
		if err != nil {
			return nil, err
		}
		vres := NewViewedUserMedia(res, "default")
		return vres, nil
	}
}

// NewRemoveEndpoint returns an endpoint function that calls the method
// "remove" of service "password-auth".
func NewRemoveEndpoint(s Service, authJWTFn security.AuthJWTFunc, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*RemovePayload)
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
		return nil, s.Remove(ctx, p)
	}
}

// NewChangePasswordEndpoint returns an endpoint function that calls the method
// "change-password" of service "password-auth".
func NewChangePasswordEndpoint(s Service, authJWTFn security.AuthJWTFunc, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*ChangePasswordParams)
		var err error
		sc := security.JWTScheme{
			Name:           "jwt",
			Scopes:         []string{},
			RequiredScopes: []string{},
		}
		ctx, err = authJWTFn(ctx, p.Authorization, &sc)
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
		return nil, s.ChangePassword(ctx, p)
	}
}

// NewResetEndpoint returns an endpoint function that calls the method "reset"
// of service "password-auth".
func NewResetEndpoint(s Service, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*ResetPayload)
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
		return nil, s.Reset(ctx, p)
	}
}

// NewConfirmResetEndpoint returns an endpoint function that calls the method
// "confirm-reset" of service "password-auth".
func NewConfirmResetEndpoint(s Service, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*ResetPasswordParams)
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
		return nil, s.ConfirmReset(ctx, p)
	}
}

// NewCheckEmailAvailableEndpoint returns an endpoint function that calls the
// method "check-email-available" of service "password-auth".
func NewCheckEmailAvailableEndpoint(s Service, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*CheckEmailAvailablePayload)
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
		return s.CheckEmailAvailable(ctx, p)
	}
}

// NewCheckPhoneAvailableEndpoint returns an endpoint function that calls the
// method "check-phone-available" of service "password-auth".
func NewCheckPhoneAvailableEndpoint(s Service, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*CheckPhoneAvailablePayload)
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
		return s.CheckPhoneAvailable(ctx, p)
	}
}
