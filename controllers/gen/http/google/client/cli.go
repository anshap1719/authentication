// Code generated by goa v3.0.6, DO NOT EDIT.
//
// google HTTP client CLI support package
//
// Command:
// $ goa gen github.com/anshap1719/authentication/design

package client

import (
	google "github.com/anshap1719/authentication/controllers/gen/google"
)

// BuildRegisterURLPayload builds the payload for the google register-url
// endpoint from CLI flags.
func BuildRegisterURLPayload(googleRegisterURLAPIKey string, googleRegisterURLRedirectURL string) (*google.RegisterURLPayload, error) {
	var aPIKey *string
	{
		if googleRegisterURLAPIKey != "" {
			aPIKey = &googleRegisterURLAPIKey
		}
	}
	var redirectURL *string
	{
		if googleRegisterURLRedirectURL != "" {
			redirectURL = &googleRegisterURLRedirectURL
		}
	}
	payload := &google.RegisterURLPayload{
		APIKey:      aPIKey,
		RedirectURL: redirectURL,
	}
	return payload, nil
}

// BuildAttachToAccountPayload builds the payload for the google
// attach-to-account endpoint from CLI flags.
func BuildAttachToAccountPayload(googleAttachToAccountAuthorization string, googleAttachToAccountXSession string, googleAttachToAccountAPIKey string, googleAttachToAccountRedirectURL string) (*google.AttachToAccountPayload, error) {
	var authorization *string
	{
		if googleAttachToAccountAuthorization != "" {
			authorization = &googleAttachToAccountAuthorization
		}
	}
	var xSession *string
	{
		if googleAttachToAccountXSession != "" {
			xSession = &googleAttachToAccountXSession
		}
	}
	var aPIKey *string
	{
		if googleAttachToAccountAPIKey != "" {
			aPIKey = &googleAttachToAccountAPIKey
		}
	}
	var redirectURL *string
	{
		if googleAttachToAccountRedirectURL != "" {
			redirectURL = &googleAttachToAccountRedirectURL
		}
	}
	payload := &google.AttachToAccountPayload{
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
		RedirectURL:   redirectURL,
	}
	return payload, nil
}

// BuildDetachFromAccountPayload builds the payload for the google
// detach-from-account endpoint from CLI flags.
func BuildDetachFromAccountPayload(googleDetachFromAccountAuthorization string, googleDetachFromAccountXSession string, googleDetachFromAccountAPIKey string) (*google.DetachFromAccountPayload, error) {
	var authorization *string
	{
		if googleDetachFromAccountAuthorization != "" {
			authorization = &googleDetachFromAccountAuthorization
		}
	}
	var xSession *string
	{
		if googleDetachFromAccountXSession != "" {
			xSession = &googleDetachFromAccountXSession
		}
	}
	var aPIKey *string
	{
		if googleDetachFromAccountAPIKey != "" {
			aPIKey = &googleDetachFromAccountAPIKey
		}
	}
	payload := &google.DetachFromAccountPayload{
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
	return payload, nil
}

// BuildReceivePayload builds the payload for the google receive endpoint from
// CLI flags.
func BuildReceivePayload(googleReceiveCode string, googleReceiveState string, googleReceiveAuthorization string, googleReceiveXSession string, googleReceiveRedirectURL string, googleReceiveAPIKey string) (*google.ReceivePayload, error) {
	var code string
	{
		code = googleReceiveCode
	}
	var state string
	{
		state = googleReceiveState
	}
	var authorization *string
	{
		if googleReceiveAuthorization != "" {
			authorization = &googleReceiveAuthorization
		}
	}
	var xSession *string
	{
		if googleReceiveXSession != "" {
			xSession = &googleReceiveXSession
		}
	}
	var redirectURL *string
	{
		if googleReceiveRedirectURL != "" {
			redirectURL = &googleReceiveRedirectURL
		}
	}
	var aPIKey *string
	{
		if googleReceiveAPIKey != "" {
			aPIKey = &googleReceiveAPIKey
		}
	}
	payload := &google.ReceivePayload{
		Code:          &code,
		State:         &state,
		Authorization: authorization,
		XSession:      xSession,
		RedirectURL:   redirectURL,
		APIKey:        aPIKey,
	}
	return payload, nil
}
