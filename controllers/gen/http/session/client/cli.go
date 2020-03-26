// Code generated by goa v3.0.6, DO NOT EDIT.
//
// session HTTP client CLI support package
//
// Command:
// $ goa gen github.com/anshap1719/go-authentication/design

package client

import (
	"encoding/json"
	"fmt"

	session "github.com/anshap1719/go-authentication/controllers/gen/session"
	goa "goa.design/goa/v3/pkg"
)

// BuildRefreshPayload builds the payload for the session refresh endpoint from
// CLI flags.
func BuildRefreshPayload(sessionRefreshXSession string, sessionRefreshAPIKey string) (*session.RefreshPayload, error) {
	var xSession string
	{
		xSession = sessionRefreshXSession
	}
	var aPIKey *string
	{
		if sessionRefreshAPIKey != "" {
			aPIKey = &sessionRefreshAPIKey
		}
	}
	payload := &session.RefreshPayload{
		XSession: &xSession,
		APIKey:   aPIKey,
	}
	return payload, nil
}

// BuildLogoutPayload builds the payload for the session logout endpoint from
// CLI flags.
func BuildLogoutPayload(sessionLogoutAuthorization string, sessionLogoutXSession string, sessionLogoutAPIKey string) (*session.LogoutPayload, error) {
	var authorization *string
	{
		if sessionLogoutAuthorization != "" {
			authorization = &sessionLogoutAuthorization
		}
	}
	var xSession *string
	{
		if sessionLogoutXSession != "" {
			xSession = &sessionLogoutXSession
		}
	}
	var aPIKey *string
	{
		if sessionLogoutAPIKey != "" {
			aPIKey = &sessionLogoutAPIKey
		}
	}
	payload := &session.LogoutPayload{
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
	return payload, nil
}

// BuildLogoutOtherPayload builds the payload for the session logout-other
// endpoint from CLI flags.
func BuildLogoutOtherPayload(sessionLogoutOtherAuthorization string, sessionLogoutOtherXSession string, sessionLogoutOtherAPIKey string) (*session.LogoutOtherPayload, error) {
	var authorization *string
	{
		if sessionLogoutOtherAuthorization != "" {
			authorization = &sessionLogoutOtherAuthorization
		}
	}
	var xSession *string
	{
		if sessionLogoutOtherXSession != "" {
			xSession = &sessionLogoutOtherXSession
		}
	}
	var aPIKey *string
	{
		if sessionLogoutOtherAPIKey != "" {
			aPIKey = &sessionLogoutOtherAPIKey
		}
	}
	payload := &session.LogoutOtherPayload{
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
	return payload, nil
}

// BuildLogoutSpecificPayload builds the payload for the session
// logout-specific endpoint from CLI flags.
func BuildLogoutSpecificPayload(sessionLogoutSpecificSessionID string, sessionLogoutSpecificAuthorization string, sessionLogoutSpecificXSession string, sessionLogoutSpecificAPIKey string) (*session.LogoutSpecificPayload, error) {
	var sessionID string
	{
		sessionID = sessionLogoutSpecificSessionID
	}
	var authorization *string
	{
		if sessionLogoutSpecificAuthorization != "" {
			authorization = &sessionLogoutSpecificAuthorization
		}
	}
	var xSession *string
	{
		if sessionLogoutSpecificXSession != "" {
			xSession = &sessionLogoutSpecificXSession
		}
	}
	var aPIKey *string
	{
		if sessionLogoutSpecificAPIKey != "" {
			aPIKey = &sessionLogoutSpecificAPIKey
		}
	}
	payload := &session.LogoutSpecificPayload{
		SessionID:     &sessionID,
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
	return payload, nil
}

// BuildGetSessionsPayload builds the payload for the session get-sessions
// endpoint from CLI flags.
func BuildGetSessionsPayload(sessionGetSessionsAuthorization string, sessionGetSessionsXSession string, sessionGetSessionsAPIKey string) (*session.GetSessionsPayload, error) {
	var authorization *string
	{
		if sessionGetSessionsAuthorization != "" {
			authorization = &sessionGetSessionsAuthorization
		}
	}
	var xSession *string
	{
		if sessionGetSessionsXSession != "" {
			xSession = &sessionGetSessionsXSession
		}
	}
	var aPIKey *string
	{
		if sessionGetSessionsAPIKey != "" {
			aPIKey = &sessionGetSessionsAPIKey
		}
	}
	payload := &session.GetSessionsPayload{
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
	return payload, nil
}

// BuildRedeemTokenPayload builds the payload for the session redeemToken
// endpoint from CLI flags.
func BuildRedeemTokenPayload(sessionRedeemTokenBody string, sessionRedeemTokenAPIKey string) (*session.RedeemTokenPayload, error) {
	var err error
	var body RedeemTokenRequestBody
	{
		err = json.Unmarshal([]byte(sessionRedeemTokenBody), &body)
		if err != nil {
			return nil, fmt.Errorf("invalid JSON for body, example of valid JSON:\n%s", "'{\n      \"User-Agent\": \"Quasi dolor fugit id beatae.\",\n      \"token\": \"A8E7C55C-B3EA-B228-EF84-9DB3D55D57A4\"\n   }'")
		}
		err = goa.MergeErrors(err, goa.ValidateFormat("body.token", body.Token, goa.FormatUUID))

		if err != nil {
			return nil, err
		}
	}
	var aPIKey *string
	{
		if sessionRedeemTokenAPIKey != "" {
			aPIKey = &sessionRedeemTokenAPIKey
		}
	}
	v := &session.RedeemTokenPayload{
		Token:     body.Token,
		UserAgent: body.UserAgent,
	}
	v.APIKey = aPIKey
	return v, nil
}

// BuildCleanSessionsPayload builds the payload for the session clean-sessions
// endpoint from CLI flags.
func BuildCleanSessionsPayload(sessionCleanSessionsAuthorization string, sessionCleanSessionsXSession string, sessionCleanSessionsAPIKey string) (*session.CleanSessionsPayload, error) {
	var authorization *string
	{
		if sessionCleanSessionsAuthorization != "" {
			authorization = &sessionCleanSessionsAuthorization
		}
	}
	var xSession *string
	{
		if sessionCleanSessionsXSession != "" {
			xSession = &sessionCleanSessionsXSession
		}
	}
	var aPIKey *string
	{
		if sessionCleanSessionsAPIKey != "" {
			aPIKey = &sessionCleanSessionsAPIKey
		}
	}
	payload := &session.CleanSessionsPayload{
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
	return payload, nil
}

// BuildCleanLoginTokenPayload builds the payload for the session
// clean-login-token endpoint from CLI flags.
func BuildCleanLoginTokenPayload(sessionCleanLoginTokenAuthorization string, sessionCleanLoginTokenXSession string, sessionCleanLoginTokenAPIKey string) (*session.CleanLoginTokenPayload, error) {
	var authorization *string
	{
		if sessionCleanLoginTokenAuthorization != "" {
			authorization = &sessionCleanLoginTokenAuthorization
		}
	}
	var xSession *string
	{
		if sessionCleanLoginTokenXSession != "" {
			xSession = &sessionCleanLoginTokenXSession
		}
	}
	var aPIKey *string
	{
		if sessionCleanLoginTokenAPIKey != "" {
			aPIKey = &sessionCleanLoginTokenAPIKey
		}
	}
	payload := &session.CleanLoginTokenPayload{
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
	return payload, nil
}

// BuildCleanMergeTokenPayload builds the payload for the session
// clean-merge-token endpoint from CLI flags.
func BuildCleanMergeTokenPayload(sessionCleanMergeTokenAuthorization string, sessionCleanMergeTokenXSession string, sessionCleanMergeTokenAPIKey string) (*session.CleanMergeTokenPayload, error) {
	var authorization *string
	{
		if sessionCleanMergeTokenAuthorization != "" {
			authorization = &sessionCleanMergeTokenAuthorization
		}
	}
	var xSession *string
	{
		if sessionCleanMergeTokenXSession != "" {
			xSession = &sessionCleanMergeTokenXSession
		}
	}
	var aPIKey *string
	{
		if sessionCleanMergeTokenAPIKey != "" {
			aPIKey = &sessionCleanMergeTokenAPIKey
		}
	}
	payload := &session.CleanMergeTokenPayload{
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
	return payload, nil
}
