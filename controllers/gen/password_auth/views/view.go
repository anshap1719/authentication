// Code generated by goa v3.0.6, DO NOT EDIT.
//
// password-auth views
//
// Command:
// $ goa gen github.com/anshap1719/authentication/design

package views

import (
	goa "goa.design/goa/v3/pkg"
)

// UserMedia is the viewed result type that is projected based on a view.
type UserMedia struct {
	// Type to project
	Projected *UserMediaView
	// View to render
	View string
}

// UserMediaView is a type that runs validations on a projected type.
type UserMediaView struct {
	// Unique unchanging user ID
	ID *string
	// Given name for the user
	FirstName *string
	// Family name for the user
	LastName *string
	// Email attached to the account of the user
	Email *string
	// Phone Number Of the user
	Phone *string
	// When the user attempts to change their email, this is what they will change
	// it to after they verify that it belongs to them
	ChangingEmail *string
	// Whether the user has verified their email
	VerifiedEmail *bool
	// Whether the user is an administrator on the site
	IsAdmin          *bool
	UpdatedAt        *string
	IsActive         *bool
	CreatedAt        *string
	CountryPhoneCode *string
	Authorization    *string
	XSession         *string
}

var (
	// UserMediaMap is a map of attribute names in result type UserMedia indexed by
	// view name.
	UserMediaMap = map[string][]string{
		"default": []string{
			"id",
			"phone",
			"lastName",
			"updatedAt",
			"email",
			"createdAt",
			"firstName",
			"countryPhoneCode",
			"changingEmail",
			"isAdmin",
			"verifiedEmail",
			"Authorization",
			"X-Session",
		},
	}
)

// ValidateUserMedia runs the validations defined on the viewed result type
// UserMedia.
func ValidateUserMedia(result *UserMedia) (err error) {
	switch result.View {
	case "default", "":
		err = ValidateUserMediaView(result.Projected)
	default:
		err = goa.InvalidEnumValueError("view", result.View, []interface{}{"default"})
	}
	return
}

// ValidateUserMediaView runs the validations defined on UserMediaView using
// the "default" view.
func ValidateUserMediaView(result *UserMediaView) (err error) {
	if result.ID == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("id", "result"))
	}
	if result.Email == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("email", "result"))
	}
	if result.Phone == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("phone", "result"))
	}
	if result.VerifiedEmail == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("verifiedEmail", "result"))
	}
	if result.FirstName == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("firstName", "result"))
	}
	if result.LastName == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("lastName", "result"))
	}
	if result.Authorization == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("Authorization", "result"))
	}
	if result.XSession == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("X-Session", "result"))
	}
	if result.UpdatedAt != nil {
		err = goa.MergeErrors(err, goa.ValidateFormat("result.updatedAt", *result.UpdatedAt, goa.FormatDateTime))
	}
	if result.CreatedAt != nil {
		err = goa.MergeErrors(err, goa.ValidateFormat("result.createdAt", *result.CreatedAt, goa.FormatDateTime))
	}
	return
}
