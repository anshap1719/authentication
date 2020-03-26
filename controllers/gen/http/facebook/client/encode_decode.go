// Code generated by goa v3.0.6, DO NOT EDIT.
//
// facebook HTTP client encoders and decoders
//
// Command:
// $ goa gen github.com/anshap1719/go-authentication/design

package client

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/url"

	facebook "github.com/anshap1719/go-authentication/controllers/gen/facebook"
	facebookviews "github.com/anshap1719/go-authentication/controllers/gen/facebook/views"
	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
)

// BuildRegisterURLRequest instantiates a HTTP request object with method and
// path set to call the "facebook" service "register-url" endpoint
func (c *Client) BuildRegisterURLRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: RegisterURLFacebookPath()}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("facebook", "register-url", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeRegisterURLRequest returns an encoder for requests sent to the
// facebook register-url server.
func EncodeRegisterURLRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*facebook.RegisterURLPayload)
		if !ok {
			return goahttp.ErrInvalidType("facebook", "register-url", "*facebook.RegisterURLPayload", v)
		}
		if p.APIKey != nil {
			req.Header.Set("API-Key", *p.APIKey)
		}
		return nil
	}
}

// DecodeRegisterURLResponse returns a decoder for responses returned by the
// facebook register-url endpoint. restoreBody controls whether the response
// body should be restored after having been read.
func DecodeRegisterURLResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
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
				body string
				err  error
			)
			err = decoder(resp).Decode(&body)
			if err != nil {
				return nil, goahttp.ErrDecodingError("facebook", "register-url", err)
			}
			return body, nil
		default:
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("facebook", "register-url", resp.StatusCode, string(body))
		}
	}
}

// BuildAttachToAccountRequest instantiates a HTTP request object with method
// and path set to call the "facebook" service "attach-to-account" endpoint
func (c *Client) BuildAttachToAccountRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: AttachToAccountFacebookPath()}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("facebook", "attach-to-account", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeAttachToAccountRequest returns an encoder for requests sent to the
// facebook attach-to-account server.
func EncodeAttachToAccountRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*facebook.AttachToAccountPayload)
		if !ok {
			return goahttp.ErrInvalidType("facebook", "attach-to-account", "*facebook.AttachToAccountPayload", v)
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

// DecodeAttachToAccountResponse returns a decoder for responses returned by
// the facebook attach-to-account endpoint. restoreBody controls whether the
// response body should be restored after having been read.
func DecodeAttachToAccountResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
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
				body string
				err  error
			)
			err = decoder(resp).Decode(&body)
			if err != nil {
				return nil, goahttp.ErrDecodingError("facebook", "attach-to-account", err)
			}
			return body, nil
		default:
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("facebook", "attach-to-account", resp.StatusCode, string(body))
		}
	}
}

// BuildDetachFromAccountRequest instantiates a HTTP request object with method
// and path set to call the "facebook" service "detach-from-account" endpoint
func (c *Client) BuildDetachFromAccountRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: DetachFromAccountFacebookPath()}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("facebook", "detach-from-account", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeDetachFromAccountRequest returns an encoder for requests sent to the
// facebook detach-from-account server.
func EncodeDetachFromAccountRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*facebook.DetachFromAccountPayload)
		if !ok {
			return goahttp.ErrInvalidType("facebook", "detach-from-account", "*facebook.DetachFromAccountPayload", v)
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

// DecodeDetachFromAccountResponse returns a decoder for responses returned by
// the facebook detach-from-account endpoint. restoreBody controls whether the
// response body should be restored after having been read.
func DecodeDetachFromAccountResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
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
			return nil, goahttp.ErrInvalidResponse("facebook", "detach-from-account", resp.StatusCode, string(body))
		}
	}
}

// BuildReceiveRequest instantiates a HTTP request object with method and path
// set to call the "facebook" service "receive" endpoint
func (c *Client) BuildReceiveRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: ReceiveFacebookPath()}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("facebook", "receive", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeReceiveRequest returns an encoder for requests sent to the facebook
// receive server.
func EncodeReceiveRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*facebook.ReceivePayload)
		if !ok {
			return goahttp.ErrInvalidType("facebook", "receive", "*facebook.ReceivePayload", v)
		}
		if p.Authorization != nil {
			req.Header.Set("Authorization", *p.Authorization)
		}
		if p.XSession != nil {
			req.Header.Set("X-Session", *p.XSession)
		}
		if p.RedirectURL != nil {
			req.Header.Set("RedirectURL", *p.RedirectURL)
		}
		if p.APIKey != nil {
			req.Header.Set("API-Key", *p.APIKey)
		}
		values := req.URL.Query()
		if p.Code != nil {
			values.Add("code", *p.Code)
		}
		if p.State != nil {
			values.Add("state", *p.State)
		}
		req.URL.RawQuery = values.Encode()
		return nil
	}
}

// DecodeReceiveResponse returns a decoder for responses returned by the
// facebook receive endpoint. restoreBody controls whether the response body
// should be restored after having been read.
func DecodeReceiveResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
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
				body ReceiveResponseBody
				err  error
			)
			err = decoder(resp).Decode(&body)
			if err != nil {
				return nil, goahttp.ErrDecodingError("facebook", "receive", err)
			}
			var (
				authorization string
				xSession      string
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
				return nil, goahttp.ErrValidationError("facebook", "receive", err)
			}
			p := NewReceiveUserMediaOK(&body, authorization, xSession)
			view := "default"
			vres := &facebookviews.UserMedia{p, view}
			if err = facebookviews.ValidateUserMedia(vres); err != nil {
				return nil, goahttp.ErrValidationError("facebook", "receive", err)
			}
			res := facebook.NewUserMedia(vres)
			return res, nil
		default:
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("facebook", "receive", resp.StatusCode, string(body))
		}
	}
}
