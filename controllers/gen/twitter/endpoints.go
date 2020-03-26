// Code generated by goa v3.0.6, DO NOT EDIT.
//
// twitter endpoints
//
// Command:
// $ goa gen github.com/anshap1719/authentication/design

package twitter

import (
	"context"

	goa "goa.design/goa/v3/pkg"
	"goa.design/goa/v3/security"
)

// Endpoints wraps the "twitter" service endpoints.
type Endpoints struct {
	RegisterURL       goa.Endpoint
	AttachToAccount   goa.Endpoint
	DetachFromAccount goa.Endpoint
	Receive           goa.Endpoint
}

// NewEndpoints wraps the methods of the "twitter" service with endpoints.
func NewEndpoints(s Service) *Endpoints {
	// Casting service to Auther interface
	a := s.(Auther)
	return &Endpoints{
		RegisterURL:       NewRegisterURLEndpoint(s, a.APIKeyAuth),
		AttachToAccount:   NewAttachToAccountEndpoint(s, a.JWTAuth, a.APIKeyAuth),
		DetachFromAccount: NewDetachFromAccountEndpoint(s, a.JWTAuth, a.APIKeyAuth),
		Receive:           NewReceiveEndpoint(s, a.APIKeyAuth),
	}
}

// Use applies the given middleware to all the "twitter" service endpoints.
func (e *Endpoints) Use(m func(goa.Endpoint) goa.Endpoint) {
	e.RegisterURL = m(e.RegisterURL)
	e.AttachToAccount = m(e.AttachToAccount)
	e.DetachFromAccount = m(e.DetachFromAccount)
	e.Receive = m(e.Receive)
}

// NewRegisterURLEndpoint returns an endpoint function that calls the method
// "register-url" of service "twitter".
func NewRegisterURLEndpoint(s Service, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*RegisterURLPayload)
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
		return s.RegisterURL(ctx, p)
	}
}

// NewAttachToAccountEndpoint returns an endpoint function that calls the
// method "attach-to-account" of service "twitter".
func NewAttachToAccountEndpoint(s Service, authJWTFn security.AuthJWTFunc, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*AttachToAccountPayload)
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
		return s.AttachToAccount(ctx, p)
	}
}

// NewDetachFromAccountEndpoint returns an endpoint function that calls the
// method "detach-from-account" of service "twitter".
func NewDetachFromAccountEndpoint(s Service, authJWTFn security.AuthJWTFunc, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*DetachFromAccountPayload)
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
		return nil, s.DetachFromAccount(ctx, p)
	}
}

// NewReceiveEndpoint returns an endpoint function that calls the method
// "receive" of service "twitter".
func NewReceiveEndpoint(s Service, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*ReceivePayload)
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
		res, err := s.Receive(ctx, p)
		if err != nil {
			return nil, err
		}
		vres := NewViewedUserMedia(res, "default")
		return vres, nil
	}
}
