// Code generated by goa v3.0.6, DO NOT EDIT.
//
// user HTTP client encoders and decoders
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

	user "github.com/anshap1719/authentication/controllers/gen/user"
	userviews "github.com/anshap1719/authentication/controllers/gen/user/views"
	goahttp "goa.design/goa/v3/http"
)

// BuildGetAuthsRequest instantiates a HTTP request object with method and path
// set to call the "user" service "getAuths" endpoint
func (c *Client) BuildGetAuthsRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: GetAuthsUserPath()}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("user", "getAuths", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeGetAuthsRequest returns an encoder for requests sent to the user
// getAuths server.
func EncodeGetAuthsRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*user.GetAuthsPayload)
		if !ok {
			return goahttp.ErrInvalidType("user", "getAuths", "*user.GetAuthsPayload", v)
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
		if p.UserID != nil {
			values.Add("userID", *p.UserID)
		}
		req.URL.RawQuery = values.Encode()
		return nil
	}
}

// DecodeGetAuthsResponse returns a decoder for responses returned by the user
// getAuths endpoint. restoreBody controls whether the response body should be
// restored after having been read.
func DecodeGetAuthsResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
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
				body GetAuthsResponseBody
				err  error
			)
			err = decoder(resp).Decode(&body)
			if err != nil {
				return nil, goahttp.ErrDecodingError("user", "getAuths", err)
			}
			p := NewGetAuthsAuthStatusMediaOK(&body)
			view := "default"
			vres := &userviews.AuthStatusMedia{p, view}
			if err = userviews.ValidateAuthStatusMedia(vres); err != nil {
				return nil, goahttp.ErrValidationError("user", "getAuths", err)
			}
			res := user.NewAuthStatusMedia(vres)
			return res, nil
		default:
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("user", "getAuths", resp.StatusCode, string(body))
		}
	}
}

// BuildDeactivateRequest instantiates a HTTP request object with method and
// path set to call the "user" service "deactivate" endpoint
func (c *Client) BuildDeactivateRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: DeactivateUserPath()}
	req, err := http.NewRequest("DELETE", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("user", "deactivate", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeDeactivateRequest returns an encoder for requests sent to the user
// deactivate server.
func EncodeDeactivateRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*user.DeactivatePayload)
		if !ok {
			return goahttp.ErrInvalidType("user", "deactivate", "*user.DeactivatePayload", v)
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
		if p.ID != nil {
			values.Add("id", *p.ID)
		}
		if p.Admin != nil {
			values.Add("admin", *p.Admin)
		}
		req.URL.RawQuery = values.Encode()
		return nil
	}
}

// DecodeDeactivateResponse returns a decoder for responses returned by the
// user deactivate endpoint. restoreBody controls whether the response body
// should be restored after having been read.
func DecodeDeactivateResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
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
			return nil, goahttp.ErrInvalidResponse("user", "deactivate", resp.StatusCode, string(body))
		}
	}
}

// BuildGetUserRequest instantiates a HTTP request object with method and path
// set to call the "user" service "getUser" endpoint
func (c *Client) BuildGetUserRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: GetUserUserPath()}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("user", "getUser", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeGetUserRequest returns an encoder for requests sent to the user
// getUser server.
func EncodeGetUserRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*user.GetUserPayload)
		if !ok {
			return goahttp.ErrInvalidType("user", "getUser", "*user.GetUserPayload", v)
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

// DecodeGetUserResponse returns a decoder for responses returned by the user
// getUser endpoint. restoreBody controls whether the response body should be
// restored after having been read.
func DecodeGetUserResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
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
				body GetUserResponseBody
				err  error
			)
			err = decoder(resp).Decode(&body)
			if err != nil {
				return nil, goahttp.ErrDecodingError("user", "getUser", err)
			}
			p := NewGetUserUserMediaOK(&body)
			view := "default"
			vres := &userviews.UserMedia{p, view}
			if err = userviews.ValidateUserMedia(vres); err != nil {
				return nil, goahttp.ErrValidationError("user", "getUser", err)
			}
			res := user.NewUserMedia(vres)
			return res, nil
		default:
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("user", "getUser", resp.StatusCode, string(body))
		}
	}
}

// BuildValidateEmailRequest instantiates a HTTP request object with method and
// path set to call the "user" service "validate-email" endpoint
func (c *Client) BuildValidateEmailRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	var (
		validateID string
	)
	{
		p, ok := v.(*user.ValidateEmailPayload)
		if !ok {
			return nil, goahttp.ErrInvalidType("user", "validate-email", "*user.ValidateEmailPayload", v)
		}
		if p.ValidateID != nil {
			validateID = *p.ValidateID
		}
	}
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: ValidateEmailUserPath(validateID)}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("user", "validate-email", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeValidateEmailRequest returns an encoder for requests sent to the user
// validate-email server.
func EncodeValidateEmailRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*user.ValidateEmailPayload)
		if !ok {
			return goahttp.ErrInvalidType("user", "validate-email", "*user.ValidateEmailPayload", v)
		}
		if p.APIKey != nil {
			req.Header.Set("API-Key", *p.APIKey)
		}
		return nil
	}
}

// DecodeValidateEmailResponse returns a decoder for responses returned by the
// user validate-email endpoint. restoreBody controls whether the response body
// should be restored after having been read.
func DecodeValidateEmailResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
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
			return nil, goahttp.ErrInvalidResponse("user", "validate-email", resp.StatusCode, string(body))
		}
	}
}

// BuildUpdateUserRequest instantiates a HTTP request object with method and
// path set to call the "user" service "update-user" endpoint
func (c *Client) BuildUpdateUserRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: UpdateUserUserPath()}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("user", "update-user", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeUpdateUserRequest returns an encoder for requests sent to the user
// update-user server.
func EncodeUpdateUserRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*user.UserUpdateParams)
		if !ok {
			return goahttp.ErrInvalidType("user", "update-user", "*user.UserUpdateParams", v)
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
		body := NewUpdateUserRequestBody(p)
		if err := encoder(req).Encode(&body); err != nil {
			return goahttp.ErrEncodingError("user", "update-user", err)
		}
		return nil
	}
}

// DecodeUpdateUserResponse returns a decoder for responses returned by the
// user update-user endpoint. restoreBody controls whether the response body
// should be restored after having been read.
func DecodeUpdateUserResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
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
				body UpdateUserResponseBody
				err  error
			)
			err = decoder(resp).Decode(&body)
			if err != nil {
				return nil, goahttp.ErrDecodingError("user", "update-user", err)
			}
			p := NewUpdateUserUserMediaOK(&body)
			view := "default"
			vres := &userviews.UserMedia{p, view}
			if err = userviews.ValidateUserMedia(vres); err != nil {
				return nil, goahttp.ErrValidationError("user", "update-user", err)
			}
			res := user.NewUserMedia(vres)
			return res, nil
		default:
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("user", "update-user", resp.StatusCode, string(body))
		}
	}
}

// BuildResendVerifyEmailRequest instantiates a HTTP request object with method
// and path set to call the "user" service "resend-verify-email" endpoint
func (c *Client) BuildResendVerifyEmailRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: ResendVerifyEmailUserPath()}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("user", "resend-verify-email", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeResendVerifyEmailRequest returns an encoder for requests sent to the
// user resend-verify-email server.
func EncodeResendVerifyEmailRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*user.ResendVerifyEmailPayload)
		if !ok {
			return goahttp.ErrInvalidType("user", "resend-verify-email", "*user.ResendVerifyEmailPayload", v)
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

// DecodeResendVerifyEmailResponse returns a decoder for responses returned by
// the user resend-verify-email endpoint. restoreBody controls whether the
// response body should be restored after having been read.
func DecodeResendVerifyEmailResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
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
			return nil, goahttp.ErrInvalidResponse("user", "resend-verify-email", resp.StatusCode, string(body))
		}
	}
}

// BuildUpdatePhoneRequest instantiates a HTTP request object with method and
// path set to call the "user" service "update-phone" endpoint
func (c *Client) BuildUpdatePhoneRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: UpdatePhoneUserPath()}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("user", "update-phone", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeUpdatePhoneRequest returns an encoder for requests sent to the user
// update-phone server.
func EncodeUpdatePhoneRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*user.UpdatePhonePayload)
		if !ok {
			return goahttp.ErrInvalidType("user", "update-phone", "*user.UpdatePhonePayload", v)
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
		if p.Phone != nil {
			values.Add("phone", *p.Phone)
		}
		if p.Country != nil {
			values.Add("country", *p.Country)
		}
		req.URL.RawQuery = values.Encode()
		return nil
	}
}

// DecodeUpdatePhoneResponse returns a decoder for responses returned by the
// user update-phone endpoint. restoreBody controls whether the response body
// should be restored after having been read.
func DecodeUpdatePhoneResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
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
			return nil, goahttp.ErrInvalidResponse("user", "update-phone", resp.StatusCode, string(body))
		}
	}
}

// BuildResendOtpRequest instantiates a HTTP request object with method and
// path set to call the "user" service "resend-otp" endpoint
func (c *Client) BuildResendOtpRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: ResendOtpUserPath()}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("user", "resend-otp", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeResendOtpRequest returns an encoder for requests sent to the user
// resend-otp server.
func EncodeResendOtpRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*user.ResendOtpPayload)
		if !ok {
			return goahttp.ErrInvalidType("user", "resend-otp", "*user.ResendOtpPayload", v)
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

// DecodeResendOtpResponse returns a decoder for responses returned by the user
// resend-otp endpoint. restoreBody controls whether the response body should
// be restored after having been read.
func DecodeResendOtpResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
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
			return nil, goahttp.ErrInvalidResponse("user", "resend-otp", resp.StatusCode, string(body))
		}
	}
}

// BuildVerifyPhoneRequest instantiates a HTTP request object with method and
// path set to call the "user" service "verify-phone" endpoint
func (c *Client) BuildVerifyPhoneRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: VerifyPhoneUserPath()}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("user", "verify-phone", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeVerifyPhoneRequest returns an encoder for requests sent to the user
// verify-phone server.
func EncodeVerifyPhoneRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*user.VerifyPhonePayload)
		if !ok {
			return goahttp.ErrInvalidType("user", "verify-phone", "*user.VerifyPhonePayload", v)
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
		if p.Otp != nil {
			values.Add("otp", *p.Otp)
		}
		req.URL.RawQuery = values.Encode()
		return nil
	}
}

// DecodeVerifyPhoneResponse returns a decoder for responses returned by the
// user verify-phone endpoint. restoreBody controls whether the response body
// should be restored after having been read.
func DecodeVerifyPhoneResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
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
			return nil, goahttp.ErrInvalidResponse("user", "verify-phone", resp.StatusCode, string(body))
		}
	}
}
