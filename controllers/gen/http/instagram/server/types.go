// Code generated by goa v3.0.6, DO NOT EDIT.
//
// instagram HTTP server types
//
// Command:
// $ goa gen github.com/anshap1719/go-authentication/design

package server

import (
	instagram "github.com/anshap1719/go-authentication/controllers/gen/instagram"
	instagramviews "github.com/anshap1719/go-authentication/controllers/gen/instagram/views"
)

// ReceiveResponseBody is the type of the "instagram" service "receive"
// endpoint HTTP response body.
type ReceiveResponseBody struct {
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
	VerifiedEmail bool `form:"verifiedEmail" json:"verifiedEmail" xml:"verifiedEmail"`
}

// NewReceiveResponseBody builds the HTTP response body from the result of the
// "receive" endpoint of the "instagram" service.
func NewReceiveResponseBody(res *instagramviews.UserMediaView) *ReceiveResponseBody {
	body := &ReceiveResponseBody{
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
	}
	return body
}

// NewRegisterURLPayload builds a instagram service register-url endpoint
// payload.
func NewRegisterURLPayload(aPIKey *string, redirectURL *string) *instagram.RegisterURLPayload {
	return &instagram.RegisterURLPayload{
		APIKey:      aPIKey,
		RedirectURL: redirectURL,
	}
}

// NewAttachToAccountPayload builds a instagram service attach-to-account
// endpoint payload.
func NewAttachToAccountPayload(authorization *string, xSession *string, aPIKey *string, redirectURL *string) *instagram.AttachToAccountPayload {
	return &instagram.AttachToAccountPayload{
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
		RedirectURL:   redirectURL,
	}
}

// NewDetachFromAccountPayload builds a instagram service detach-from-account
// endpoint payload.
func NewDetachFromAccountPayload(authorization *string, xSession *string, aPIKey *string) *instagram.DetachFromAccountPayload {
	return &instagram.DetachFromAccountPayload{
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
}

// NewReceivePayload builds a instagram service receive endpoint payload.
func NewReceivePayload(code string, state string, authorization *string, xSession *string, redirectURL *string, aPIKey *string) *instagram.ReceivePayload {
	return &instagram.ReceivePayload{
		Code:          &code,
		State:         &state,
		Authorization: authorization,
		XSession:      xSession,
		RedirectURL:   redirectURL,
		APIKey:        aPIKey,
	}
}
