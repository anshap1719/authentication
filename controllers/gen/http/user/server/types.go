// Code generated by goa v3.0.6, DO NOT EDIT.
//
// user HTTP server types
//
// Command:
// $ goa gen github.com/anshap1719/authentication/design

package server

import (
	user "github.com/anshap1719/authentication/controllers/gen/user"
	userviews "github.com/anshap1719/authentication/controllers/gen/user/views"
)

// UpdateUserRequestBody is the type of the "user" service "update-user"
// endpoint HTTP request body.
type UpdateUserRequestBody struct {
	// Given name for the user
	FirstName *string `form:"firstName,omitempty" json:"firstName,omitempty" xml:"firstName,omitempty"`
	// Family name for the user
	LastName *string `form:"lastName,omitempty" json:"lastName,omitempty" xml:"lastName,omitempty"`
	// Email attached to the account of the user
	Email *string `form:"email,omitempty" json:"email,omitempty" xml:"email,omitempty"`
	// Phone Number Of the user
	Phone *string `form:"phone,omitempty" json:"phone,omitempty" xml:"phone,omitempty"`
	// When the user attempts to change their email, this is what they will change
	// it to after they verify that it belongs to them
	ChangingEmail *string `form:"changingEmail,omitempty" json:"changingEmail,omitempty" xml:"changingEmail,omitempty"`
	// Whether the user has verified their email
	VerifiedEmail *bool `form:"verifiedEmail,omitempty" json:"verifiedEmail,omitempty" xml:"verifiedEmail,omitempty"`
	// Whether the user is an administrator on the site
	IsAdmin          *bool   `form:"isAdmin,omitempty" json:"isAdmin,omitempty" xml:"isAdmin,omitempty"`
	CountryPhoneCode *string `form:"countryPhoneCode,omitempty" json:"countryPhoneCode,omitempty" xml:"countryPhoneCode,omitempty"`
}

// GetAuthsResponseBody is the type of the "user" service "getAuths" endpoint
// HTTP response body.
type GetAuthsResponseBody struct {
	// True if user has google Oauth signin
	Google bool `form:"google" json:"google" xml:"google"`
	// True if user has facebook Oauth signin
	Facebook bool `form:"facebook" json:"facebook" xml:"facebook"`
	// True if user has twitter Oauth signin
	Twitter bool `form:"twitter" json:"twitter" xml:"twitter"`
	// True if user has linkedin Oauth signin
	Linkedin bool `form:"linkedin" json:"linkedin" xml:"linkedin"`
	// True if user has microsoft Oauth signin
	Instagram bool `form:"instagram" json:"instagram" xml:"instagram"`
	// True if user has password signin
	Standard bool `form:"standard" json:"standard" xml:"standard"`
}

// GetUserResponseBody is the type of the "user" service "getUser" endpoint
// HTTP response body.
type GetUserResponseBody struct {
	// Unique unchanging user ID
	ID string `form:"id" json:"id" xml:"id"`
	// Phone Number Of the user
	Phone string `form:"phone" json:"phone" xml:"phone"`
	// Family name for the user
	LastName  string  `form:"lastName" json:"lastName" xml:"lastName"`
	UpdatedAt *string `form:"updatedAt,omitempty" json:"updatedAt,omitempty" xml:"updatedAt,omitempty"`
	// Email attached to the account of the user
	Email     string  `form:"email" json:"email" xml:"email"`
	CreatedAt *string `form:"createdAt,omitempty" json:"createdAt,omitempty" xml:"createdAt,omitempty"`
	// Given name for the user
	FirstName        string  `form:"firstName" json:"firstName" xml:"firstName"`
	CountryPhoneCode *string `form:"countryPhoneCode,omitempty" json:"countryPhoneCode,omitempty" xml:"countryPhoneCode,omitempty"`
	// When the user attempts to change their email, this is what they will change
	// it to after they verify that it belongs to them
	ChangingEmail *string `form:"changingEmail,omitempty" json:"changingEmail,omitempty" xml:"changingEmail,omitempty"`
	// Whether the user is an administrator on the site
	IsAdmin *bool `form:"isAdmin,omitempty" json:"isAdmin,omitempty" xml:"isAdmin,omitempty"`
	// Whether the user has verified their email
	VerifiedEmail bool   `form:"verifiedEmail" json:"verifiedEmail" xml:"verifiedEmail"`
	Authorization string `form:"Authorization" json:"Authorization" xml:"Authorization"`
	XSession      string `form:"X-Session" json:"X-Session" xml:"X-Session"`
}

// UpdateUserResponseBody is the type of the "user" service "update-user"
// endpoint HTTP response body.
type UpdateUserResponseBody struct {
	// Unique unchanging user ID
	ID string `form:"id" json:"id" xml:"id"`
	// Phone Number Of the user
	Phone string `form:"phone" json:"phone" xml:"phone"`
	// Family name for the user
	LastName  string  `form:"lastName" json:"lastName" xml:"lastName"`
	UpdatedAt *string `form:"updatedAt,omitempty" json:"updatedAt,omitempty" xml:"updatedAt,omitempty"`
	// Email attached to the account of the user
	Email     string  `form:"email" json:"email" xml:"email"`
	CreatedAt *string `form:"createdAt,omitempty" json:"createdAt,omitempty" xml:"createdAt,omitempty"`
	// Given name for the user
	FirstName        string  `form:"firstName" json:"firstName" xml:"firstName"`
	CountryPhoneCode *string `form:"countryPhoneCode,omitempty" json:"countryPhoneCode,omitempty" xml:"countryPhoneCode,omitempty"`
	// When the user attempts to change their email, this is what they will change
	// it to after they verify that it belongs to them
	ChangingEmail *string `form:"changingEmail,omitempty" json:"changingEmail,omitempty" xml:"changingEmail,omitempty"`
	// Whether the user is an administrator on the site
	IsAdmin *bool `form:"isAdmin,omitempty" json:"isAdmin,omitempty" xml:"isAdmin,omitempty"`
	// Whether the user has verified their email
	VerifiedEmail bool   `form:"verifiedEmail" json:"verifiedEmail" xml:"verifiedEmail"`
	Authorization string `form:"Authorization" json:"Authorization" xml:"Authorization"`
	XSession      string `form:"X-Session" json:"X-Session" xml:"X-Session"`
}

// NewGetAuthsResponseBody builds the HTTP response body from the result of the
// "getAuths" endpoint of the "user" service.
func NewGetAuthsResponseBody(res *userviews.AuthStatusMediaView) *GetAuthsResponseBody {
	body := &GetAuthsResponseBody{
		Google:    *res.Google,
		Facebook:  *res.Facebook,
		Twitter:   *res.Twitter,
		Linkedin:  *res.Linkedin,
		Instagram: *res.Instagram,
		Standard:  *res.Standard,
	}
	return body
}

// NewGetUserResponseBody builds the HTTP response body from the result of the
// "getUser" endpoint of the "user" service.
func NewGetUserResponseBody(res *userviews.UserMediaView) *GetUserResponseBody {
	body := &GetUserResponseBody{
		ID:               *res.ID,
		FirstName:        *res.FirstName,
		LastName:         *res.LastName,
		Email:            *res.Email,
		Phone:            *res.Phone,
		ChangingEmail:    res.ChangingEmail,
		VerifiedEmail:    *res.VerifiedEmail,
		IsAdmin:          res.IsAdmin,
		UpdatedAt:        res.UpdatedAt,
		CreatedAt:        res.CreatedAt,
		CountryPhoneCode: res.CountryPhoneCode,
		Authorization:    *res.Authorization,
		XSession:         *res.XSession,
	}
	return body
}

// NewUpdateUserResponseBody builds the HTTP response body from the result of
// the "update-user" endpoint of the "user" service.
func NewUpdateUserResponseBody(res *userviews.UserMediaView) *UpdateUserResponseBody {
	body := &UpdateUserResponseBody{
		ID:               *res.ID,
		FirstName:        *res.FirstName,
		LastName:         *res.LastName,
		Email:            *res.Email,
		Phone:            *res.Phone,
		ChangingEmail:    res.ChangingEmail,
		VerifiedEmail:    *res.VerifiedEmail,
		IsAdmin:          res.IsAdmin,
		UpdatedAt:        res.UpdatedAt,
		CreatedAt:        res.CreatedAt,
		CountryPhoneCode: res.CountryPhoneCode,
		Authorization:    *res.Authorization,
		XSession:         *res.XSession,
	}
	return body
}

// NewGetAuthsPayload builds a user service getAuths endpoint payload.
func NewGetAuthsPayload(userID *string, authorization *string, xSession *string, aPIKey *string) *user.GetAuthsPayload {
	return &user.GetAuthsPayload{
		UserID:        userID,
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
}

// NewDeactivatePayload builds a user service deactivate endpoint payload.
func NewDeactivatePayload(id *string, admin *string, authorization *string, xSession *string, aPIKey *string) *user.DeactivatePayload {
	return &user.DeactivatePayload{
		ID:            id,
		Admin:         admin,
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
}

// NewGetUserPayload builds a user service getUser endpoint payload.
func NewGetUserPayload(authorization *string, xSession *string, aPIKey *string) *user.GetUserPayload {
	return &user.GetUserPayload{
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
}

// NewValidateEmailPayload builds a user service validate-email endpoint
// payload.
func NewValidateEmailPayload(validateID string, aPIKey *string) *user.ValidateEmailPayload {
	return &user.ValidateEmailPayload{
		ValidateID: &validateID,
		APIKey:     aPIKey,
	}
}

// NewUpdateUserUserUpdateParams builds a user service update-user endpoint
// payload.
func NewUpdateUserUserUpdateParams(body *UpdateUserRequestBody, authorization *string, xSession *string, aPIKey *string) *user.UserUpdateParams {
	v := &user.UserUpdateParams{
		FirstName:        body.FirstName,
		LastName:         body.LastName,
		Email:            body.Email,
		Phone:            body.Phone,
		ChangingEmail:    body.ChangingEmail,
		VerifiedEmail:    body.VerifiedEmail,
		IsAdmin:          body.IsAdmin,
		CountryPhoneCode: body.CountryPhoneCode,
	}
	v.Authorization = authorization
	v.XSession = xSession
	v.APIKey = aPIKey
	return v
}

// NewResendVerifyEmailPayload builds a user service resend-verify-email
// endpoint payload.
func NewResendVerifyEmailPayload(authorization *string, xSession *string, aPIKey *string) *user.ResendVerifyEmailPayload {
	return &user.ResendVerifyEmailPayload{
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
}

// NewUpdatePhonePayload builds a user service update-phone endpoint payload.
func NewUpdatePhonePayload(phone *string, country *string, authorization *string, xSession *string, aPIKey *string) *user.UpdatePhonePayload {
	return &user.UpdatePhonePayload{
		Phone:         phone,
		Country:       country,
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
}

// NewResendOtpPayload builds a user service resend-otp endpoint payload.
func NewResendOtpPayload(authorization *string, xSession *string, aPIKey *string) *user.ResendOtpPayload {
	return &user.ResendOtpPayload{
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
}

// NewVerifyPhonePayload builds a user service verify-phone endpoint payload.
func NewVerifyPhonePayload(otp *string, authorization *string, xSession *string, aPIKey *string) *user.VerifyPhonePayload {
	return &user.VerifyPhonePayload{
		Otp:           otp,
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
}
