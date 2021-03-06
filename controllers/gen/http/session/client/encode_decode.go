// Code generated by goa v3.0.6, DO NOT EDIT.
//
// session HTTP client encoders and decoders
//
// Command:
// $ goa gen github.com/anshap1719/authentication/design

package client

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/url"

	session "github.com/anshap1719/authentication/controllers/gen/session"
	sessionviews "github.com/anshap1719/authentication/controllers/gen/session/views"
	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
)

// BuildRefreshRequest instantiates a HTTP request object with method and path
// set to call the "session" service "refresh" endpoint
func (c *Client) BuildRefreshRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: RefreshSessionPath()}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("session", "refresh", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeRefreshRequest returns an encoder for requests sent to the session
// refresh server.
func EncodeRefreshRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*session.RefreshPayload)
		if !ok {
			return goahttp.ErrInvalidType("session", "refresh", "*session.RefreshPayload", v)
		}
		if p.XSession != nil {
			req.Header.Set("X-Session", *p.XSession)
		}
		if p.APIKey != nil {
			req.Header.Set("API-Key", *p.APIKey)
		}
		return nil
	}
}

// DecodeRefreshResponse returns a decoder for responses returned by the
// session refresh endpoint. restoreBody controls whether the response body
// should be restored after having been read.
func DecodeRefreshResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
	return func(resp *http.Response) (interface{}, error) {
		if restoreBody {
			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			}()
		} else {
			defer resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusOK:
			var (
				authorization string
				xSession      string
				err           error
			)
			authorizationRaw := resp.Header.Get("Authorization")
			if authorizationRaw == "" {
				err = goa.MergeErrors(err, goa.MissingFieldError("Authorization", "header"))
			}
			authorization = authorizationRaw
			xSessionRaw := resp.Header.Get("X-Session")
			if xSessionRaw == "" {
				err = goa.MergeErrors(err, goa.MissingFieldError("X-Session", "header"))
			}
			xSession = xSessionRaw
			if err != nil {
				return nil, goahttp.ErrValidationError("session", "refresh", err)
			}
			res := NewRefreshResultOK(authorization, xSession)
			return res, nil
		default:
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("session", "refresh", resp.StatusCode, string(body))
		}
	}
}

// BuildLogoutRequest instantiates a HTTP request object with method and path
// set to call the "session" service "logout" endpoint
func (c *Client) BuildLogoutRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: LogoutSessionPath()}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("session", "logout", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeLogoutRequest returns an encoder for requests sent to the session
// logout server.
func EncodeLogoutRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*session.LogoutPayload)
		if !ok {
			return goahttp.ErrInvalidType("session", "logout", "*session.LogoutPayload", v)
		}
		if p.Authorization != nil {
			req.Header.Set("Authorization", *p.Authorization)
		}
		if p.XSession != nil {
			req.Header.Set("X-Session", *p.XSession)
		}
		if p.APIKey != nil {
			req.Header.Set("API-Key", *p.APIKey)
		}
		return nil
	}
}

// DecodeLogoutResponse returns a decoder for responses returned by the session
// logout endpoint. restoreBody controls whether the response body should be
// restored after having been read.
func DecodeLogoutResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
	return func(resp *http.Response) (interface{}, error) {
		if restoreBody {
			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			}()
		} else {
			defer resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusOK:
			return nil, nil
		default:
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("session", "logout", resp.StatusCode, string(body))
		}
	}
}

// BuildLogoutOtherRequest instantiates a HTTP request object with method and
// path set to call the "session" service "logout-other" endpoint
func (c *Client) BuildLogoutOtherRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: LogoutOtherSessionPath()}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("session", "logout-other", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeLogoutOtherRequest returns an encoder for requests sent to the session
// logout-other server.
func EncodeLogoutOtherRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*session.LogoutOtherPayload)
		if !ok {
			return goahttp.ErrInvalidType("session", "logout-other", "*session.LogoutOtherPayload", v)
		}
		if p.Authorization != nil {
			req.Header.Set("Authorization", *p.Authorization)
		}
		if p.XSession != nil {
			req.Header.Set("X-Session", *p.XSession)
		}
		if p.APIKey != nil {
			req.Header.Set("API-Key", *p.APIKey)
		}
		return nil
	}
}

// DecodeLogoutOtherResponse returns a decoder for responses returned by the
// session logout-other endpoint. restoreBody controls whether the response
// body should be restored after having been read.
func DecodeLogoutOtherResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
	return func(resp *http.Response) (interface{}, error) {
		if restoreBody {
			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			}()
		} else {
			defer resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusOK:
			return nil, nil
		default:
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("session", "logout-other", resp.StatusCode, string(body))
		}
	}
}

// BuildLogoutSpecificRequest instantiates a HTTP request object with method
// and path set to call the "session" service "logout-specific" endpoint
func (c *Client) BuildLogoutSpecificRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: LogoutSpecificSessionPath()}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("session", "logout-specific", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeLogoutSpecificRequest returns an encoder for requests sent to the
// session logout-specific server.
func EncodeLogoutSpecificRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*session.LogoutSpecificPayload)
		if !ok {
			return goahttp.ErrInvalidType("session", "logout-specific", "*session.LogoutSpecificPayload", v)
		}
		if p.Authorization != nil {
			req.Header.Set("Authorization", *p.Authorization)
		}
		if p.XSession != nil {
			req.Header.Set("X-Session", *p.XSession)
		}
		if p.APIKey != nil {
			req.Header.Set("API-Key", *p.APIKey)
		}
		values := req.URL.Query()
		if p.SessionID != nil {
			values.Add("session-id", *p.SessionID)
		}
		req.URL.RawQuery = values.Encode()
		return nil
	}
}

// DecodeLogoutSpecificResponse returns a decoder for responses returned by the
// session logout-specific endpoint. restoreBody controls whether the response
// body should be restored after having been read.
func DecodeLogoutSpecificResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
	return func(resp *http.Response) (interface{}, error) {
		if restoreBody {
			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			}()
		} else {
			defer resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusOK:
			return nil, nil
		default:
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("session", "logout-specific", resp.StatusCode, string(body))
		}
	}
}

// BuildGetSessionsRequest instantiates a HTTP request object with method and
// path set to call the "session" service "get-sessions" endpoint
func (c *Client) BuildGetSessionsRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: GetSessionsSessionPath()}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("session", "get-sessions", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeGetSessionsRequest returns an encoder for requests sent to the session
// get-sessions server.
func EncodeGetSessionsRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*session.GetSessionsPayload)
		if !ok {
			return goahttp.ErrInvalidType("session", "get-sessions", "*session.GetSessionsPayload", v)
		}
		if p.Authorization != nil {
			req.Header.Set("Authorization", *p.Authorization)
		}
		if p.XSession != nil {
			req.Header.Set("X-Session", *p.XSession)
		}
		if p.APIKey != nil {
			req.Header.Set("API-Key", *p.APIKey)
		}
		return nil
	}
}

// DecodeGetSessionsResponse returns a decoder for responses returned by the
// session get-sessions endpoint. restoreBody controls whether the response
// body should be restored after having been read.
func DecodeGetSessionsResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
	return func(resp *http.Response) (interface{}, error) {
		if restoreBody {
			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			}()
		} else {
			defer resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusOK:
			var (
				body GetSessionsResponseBody
				err  error
			)
			err = decoder(resp).Decode(&body)
			if err != nil {
				return nil, goahttp.ErrDecodingError("session", "get-sessions", err)
			}
			p := NewGetSessionsAllSessionsOK(&body)
			view := "default"
			vres := &sessionviews.AllSessions{p, view}
			if err = sessionviews.ValidateAllSessions(vres); err != nil {
				return nil, goahttp.ErrValidationError("session", "get-sessions", err)
			}
			res := session.NewAllSessions(vres)
			return res, nil
		default:
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("session", "get-sessions", resp.StatusCode, string(body))
		}
	}
}

// BuildRedeemTokenRequest instantiates a HTTP request object with method and
// path set to call the "session" service "redeemToken" endpoint
func (c *Client) BuildRedeemTokenRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: RedeemTokenSessionPath()}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("session", "redeemToken", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeRedeemTokenRequest returns an encoder for requests sent to the session
// redeemToken server.
func EncodeRedeemTokenRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*session.RedeemTokenPayload)
		if !ok {
			return goahttp.ErrInvalidType("session", "redeemToken", "*session.RedeemTokenPayload", v)
		}
		if p.APIKey != nil {
			req.Header.Set("API-Key", *p.APIKey)
		}
		body := NewRedeemTokenRequestBody(p)
		if err := encoder(req).Encode(&body); err != nil {
			return goahttp.ErrEncodingError("session", "redeemToken", err)
		}
		return nil
	}
}

// DecodeRedeemTokenResponse returns a decoder for responses returned by the
// session redeemToken endpoint. restoreBody controls whether the response body
// should be restored after having been read.
func DecodeRedeemTokenResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
	return func(resp *http.Response) (interface{}, error) {
		if restoreBody {
			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			}()
		} else {
			defer resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusCreated:
			var (
				authorization string
				xSession      string
				err           error
			)
			authorizationRaw := resp.Header.Get("Authorization")
			if authorizationRaw == "" {
				err = goa.MergeErrors(err, goa.MissingFieldError("Authorization", "header"))
			}
			authorization = authorizationRaw
			xSessionRaw := resp.Header.Get("X-Session")
			if xSessionRaw == "" {
				err = goa.MergeErrors(err, goa.MissingFieldError("X-Session", "header"))
			}
			xSession = xSessionRaw
			if err != nil {
				return nil, goahttp.ErrValidationError("session", "redeemToken", err)
			}
			res := NewRedeemTokenResultCreated(authorization, xSession)
			return res, nil
		default:
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("session", "redeemToken", resp.StatusCode, string(body))
		}
	}
}

// BuildCleanSessionsRequest instantiates a HTTP request object with method and
// path set to call the "session" service "clean-sessions" endpoint
func (c *Client) BuildCleanSessionsRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: CleanSessionsSessionPath()}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("session", "clean-sessions", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeCleanSessionsRequest returns an encoder for requests sent to the
// session clean-sessions server.
func EncodeCleanSessionsRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*session.CleanSessionsPayload)
		if !ok {
			return goahttp.ErrInvalidType("session", "clean-sessions", "*session.CleanSessionsPayload", v)
		}
		if p.Authorization != nil {
			req.Header.Set("Authorization", *p.Authorization)
		}
		if p.XSession != nil {
			req.Header.Set("X-Session", *p.XSession)
		}
		if p.APIKey != nil {
			req.Header.Set("API-Key", *p.APIKey)
		}
		return nil
	}
}

// DecodeCleanSessionsResponse returns a decoder for responses returned by the
// session clean-sessions endpoint. restoreBody controls whether the response
// body should be restored after having been read.
func DecodeCleanSessionsResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
	return func(resp *http.Response) (interface{}, error) {
		if restoreBody {
			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			}()
		} else {
			defer resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusOK:
			return nil, nil
		default:
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("session", "clean-sessions", resp.StatusCode, string(body))
		}
	}
}

// BuildCleanLoginTokenRequest instantiates a HTTP request object with method
// and path set to call the "session" service "clean-login-token" endpoint
func (c *Client) BuildCleanLoginTokenRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: CleanLoginTokenSessionPath()}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("session", "clean-login-token", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeCleanLoginTokenRequest returns an encoder for requests sent to the
// session clean-login-token server.
func EncodeCleanLoginTokenRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*session.CleanLoginTokenPayload)
		if !ok {
			return goahttp.ErrInvalidType("session", "clean-login-token", "*session.CleanLoginTokenPayload", v)
		}
		if p.Authorization != nil {
			req.Header.Set("Authorization", *p.Authorization)
		}
		if p.XSession != nil {
			req.Header.Set("X-Session", *p.XSession)
		}
		if p.APIKey != nil {
			req.Header.Set("API-Key", *p.APIKey)
		}
		return nil
	}
}

// DecodeCleanLoginTokenResponse returns a decoder for responses returned by
// the session clean-login-token endpoint. restoreBody controls whether the
// response body should be restored after having been read.
func DecodeCleanLoginTokenResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
	return func(resp *http.Response) (interface{}, error) {
		if restoreBody {
			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			}()
		} else {
			defer resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusOK:
			return nil, nil
		default:
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("session", "clean-login-token", resp.StatusCode, string(body))
		}
	}
}

// BuildCleanMergeTokenRequest instantiates a HTTP request object with method
// and path set to call the "session" service "clean-merge-token" endpoint
func (c *Client) BuildCleanMergeTokenRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: CleanMergeTokenSessionPath()}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("session", "clean-merge-token", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeCleanMergeTokenRequest returns an encoder for requests sent to the
// session clean-merge-token server.
func EncodeCleanMergeTokenRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*session.CleanMergeTokenPayload)
		if !ok {
			return goahttp.ErrInvalidType("session", "clean-merge-token", "*session.CleanMergeTokenPayload", v)
		}
		if p.Authorization != nil {
			req.Header.Set("Authorization", *p.Authorization)
		}
		if p.XSession != nil {
			req.Header.Set("X-Session", *p.XSession)
		}
		if p.APIKey != nil {
			req.Header.Set("API-Key", *p.APIKey)
		}
		return nil
	}
}

// DecodeCleanMergeTokenResponse returns a decoder for responses returned by
// the session clean-merge-token endpoint. restoreBody controls whether the
// response body should be restored after having been read.
func DecodeCleanMergeTokenResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
	return func(resp *http.Response) (interface{}, error) {
		if restoreBody {
			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			}()
		} else {
			defer resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusOK:
			return nil, nil
		default:
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("session", "clean-merge-token", resp.StatusCode, string(body))
		}
	}
}

// unmarshalSessionResponseBodyToSessionviewsSessionView builds a value of type
// *sessionviews.SessionView from a value of type *SessionResponseBody.
func unmarshalSessionResponseBodyToSessionviewsSessionView(v *SessionResponseBody) *sessionviews.SessionView {
	if v == nil {
		return nil
	}
	res := &sessionviews.SessionView{
		ID:        v.ID,
		UserID:    v.UserID,
		LastUsed:  v.LastUsed,
		Browser:   v.Browser,
		Os:        v.Os,
		IP:        v.IP,
		Location:  v.Location,
		Latitude:  v.Latitude,
		Longitude: v.Longitude,
		IsMobile:  v.IsMobile,
		MapURL:    v.MapURL,
	}

	return res
}
