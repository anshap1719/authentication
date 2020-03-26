// Code generated by goa v3.0.6, DO NOT EDIT.
//
// google HTTP server encoders and decoders
//
// Command:
// $ goa gen github.com/anshap1719/go-authentication/design

package server

import (
	"context"
	"net/http"
	"strings"

	googleviews "github.com/anshap1719/go-authentication/controllers/gen/google/views"
	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
)

// EncodeRegisterURLResponse returns an encoder for responses returned by the
// google register-url endpoint.
func EncodeRegisterURLResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, interface{}) error {
	return func(ctx context.Context, w http.ResponseWriter, v interface{}) error {
		res := v.(string)
		enc := encoder(ctx, w)
		body := res
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeRegisterURLRequest returns a decoder for requests sent to the google
// register-url endpoint.
func DecodeRegisterURLRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (interface{}, error) {
	return func(r *http.Request) (interface{}, error) {
		var (
			aPIKey      *string
			redirectURL *string
		)
		aPIKeyRaw := r.Header.Get("API-Key")
		if aPIKeyRaw != "" {
			aPIKey = &aPIKeyRaw
		}
		redirectURLRaw := r.Header.Get("RedirectURL")
		if redirectURLRaw != "" {
			redirectURL = &redirectURLRaw
		}
		payload := NewRegisterURLPayload(aPIKey, redirectURL)

		return payload, nil
	}
}

// EncodeAttachToAccountResponse returns an encoder for responses returned by
// the google attach-to-account endpoint.
func EncodeAttachToAccountResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, interface{}) error {
	return func(ctx context.Context, w http.ResponseWriter, v interface{}) error {
		res := v.(string)
		enc := encoder(ctx, w)
		body := res
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeAttachToAccountRequest returns a decoder for requests sent to the
// google attach-to-account endpoint.
func DecodeAttachToAccountRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (interface{}, error) {
	return func(r *http.Request) (interface{}, error) {
		var (
			authorization *string
			xSession      *string
			aPIKey        *string
			redirectURL   *string
		)
		authorizationRaw := r.Header.Get("Authorization")
		if authorizationRaw != "" {
			authorization = &authorizationRaw
		}
		xSessionRaw := r.Header.Get("X-Session")
		if xSessionRaw != "" {
			xSession = &xSessionRaw
		}
		aPIKeyRaw := r.Header.Get("API-Key")
		if aPIKeyRaw != "" {
			aPIKey = &aPIKeyRaw
		}
		redirectURLRaw := r.Header.Get("RedirectURL")
		if redirectURLRaw != "" {
			redirectURL = &redirectURLRaw
		}
		payload := NewAttachToAccountPayload(authorization, xSession, aPIKey, redirectURL)
		if payload.Authorization != nil {
			if strings.Contains(*payload.Authorization, " ") {
				// Remove authorization scheme prefix (e.g. "Bearer")
				cred := strings.SplitN(*payload.Authorization, " ", 2)[1]
				payload.Authorization = &cred
			}
		}

		return payload, nil
	}
}

// EncodeDetachFromAccountResponse returns an encoder for responses returned by
// the google detach-from-account endpoint.
func EncodeDetachFromAccountResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, interface{}) error {
	return func(ctx context.Context, w http.ResponseWriter, v interface{}) error {
		w.WriteHeader(http.StatusOK)
		return nil
	}
}

// DecodeDetachFromAccountRequest returns a decoder for requests sent to the
// google detach-from-account endpoint.
func DecodeDetachFromAccountRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (interface{}, error) {
	return func(r *http.Request) (interface{}, error) {
		var (
			authorization *string
			xSession      *string
			aPIKey        *string
		)
		authorizationRaw := r.Header.Get("Authorization")
		if authorizationRaw != "" {
			authorization = &authorizationRaw
		}
		xSessionRaw := r.Header.Get("X-Session")
		if xSessionRaw != "" {
			xSession = &xSessionRaw
		}
		aPIKeyRaw := r.Header.Get("API-Key")
		if aPIKeyRaw != "" {
			aPIKey = &aPIKeyRaw
		}
		payload := NewDetachFromAccountPayload(authorization, xSession, aPIKey)
		if payload.Authorization != nil {
			if strings.Contains(*payload.Authorization, " ") {
				// Remove authorization scheme prefix (e.g. "Bearer")
				cred := strings.SplitN(*payload.Authorization, " ", 2)[1]
				payload.Authorization = &cred
			}
		}

		return payload, nil
	}
}

// EncodeReceiveResponse returns an encoder for responses returned by the
// google receive endpoint.
func EncodeReceiveResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, interface{}) error {
	return func(ctx context.Context, w http.ResponseWriter, v interface{}) error {
		res := v.(*googleviews.UserMedia)
		ctx = context.WithValue(ctx, goahttp.ContentTypeKey, "application/json")
		enc := encoder(ctx, w)
		body := NewReceiveResponseBody(res.Projected)
		if res.Projected.Authorization != nil {
			w.Header().Set("Authorization", *res.Projected.Authorization)
		}
		if res.Projected.XSession != nil {
			w.Header().Set("X-Session", *res.Projected.XSession)
		}
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeReceiveRequest returns a decoder for requests sent to the google
// receive endpoint.
func DecodeReceiveRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (interface{}, error) {
	return func(r *http.Request) (interface{}, error) {
		var (
			code          string
			state         string
			authorization *string
			xSession      *string
			redirectURL   *string
			aPIKey        *string
			err           error
		)
		code = r.URL.Query().Get("code")
		if code == "" {
			err = goa.MergeErrors(err, goa.MissingFieldError("code", "query string"))
		}
		state = r.URL.Query().Get("state")
		if state == "" {
			err = goa.MergeErrors(err, goa.MissingFieldError("state", "query string"))
		}
		err = goa.MergeErrors(err, goa.ValidateFormat("state", state, goa.FormatUUID))

		authorizationRaw := r.Header.Get("Authorization")
		if authorizationRaw != "" {
			authorization = &authorizationRaw
		}
		xSessionRaw := r.Header.Get("X-Session")
		if xSessionRaw != "" {
			xSession = &xSessionRaw
		}
		redirectURLRaw := r.Header.Get("RedirectURL")
		if redirectURLRaw != "" {
			redirectURL = &redirectURLRaw
		}
		aPIKeyRaw := r.Header.Get("API-Key")
		if aPIKeyRaw != "" {
			aPIKey = &aPIKeyRaw
		}
		if err != nil {
			return nil, err
		}
		payload := NewReceivePayload(code, state, authorization, xSession, redirectURL, aPIKey)

		return payload, nil
	}
}
