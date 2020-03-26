package types

import (
	. "goa.design/goa/v3/dsl"
)

const (
	passwordPattern = `^.*[\w].*$`
	minPassLength   = 6
	maxPassLength   = 100
)

var RegisterParams = Type("register-params", func() {
	Attribute("email", String, "The email that will be attached to the account", func() {
		Format("email")
	})
	Attribute("firstName", String, "The user's given name", func() {
		MinLength(minNameLength)
		MaxLength(maxNameLength)
	})
	Attribute("lastName", String, "The user's family name", func() {
		MaxLength(maxNameLength)
	})
	Attribute("password", String, "The password associated with the new account", func() {
		Pattern(passwordPattern)
		MinLength(minPassLength)
		MaxLength(maxPassLength)
	})
	Attribute("phone", String, "The user's phone number")
	Attribute("gRecaptchaResponse", String, "The recaptcha response code")
	Attribute("Authorization", String)
	Attribute("X-Session", String)
	APIKey("api_key", "API-Key", String)
	Required("email", "password", "firstName", "lastName", "gRecaptchaResponse")
})

var LoginParams = Type("login-params", func() {
	Attribute("email", String, "The email address of the account to login to", func() {
		Format("email")
	})
	Attribute("password", String, "The password of the account to login to", func() {
		Pattern(passwordPattern)
		MinLength(minPassLength)
		MaxLength(maxPassLength)
	})
	Attribute("TwoFactor", String, "2 Factor Auth if user has enabled the feature", func() {
		MinLength(6)
		MaxLength(8)
	})
	Attribute("token", String)
	APIKey("api_key", "API-Key", String)
	Required("email", "password")
})

var ChangePasswordParams = Type("change-password-params", func() {
	Attribute("oldPassword", String, "The old password for the current user account", func() {
		Pattern(passwordPattern)
		MinLength(minPassLength)
		MaxLength(maxPassLength)
	})
	Attribute("newPassword", String, "The new password for the current user account", func() {
		Pattern(passwordPattern)
		MinLength(minPassLength)
		MaxLength(maxPassLength)
	})
	Token("Authorization")
	Token("X-Session")
	APIKey("api_key", "API-Key", String)
	Required("newPassword", "Authorization", "X-Session")
})

var ResetPasswordParams = Type("reset-password-params", func() {
	Attribute("resetCode", String, "The UUID of the password reset, send from the user's email")
	Attribute("userID", String, "The ID of the user to reset the password of")
	Attribute("newPassword", String, "The new password that will be used to login to the account", func() {
		Pattern(passwordPattern)
		MinLength(minPassLength)
		MaxLength(maxPassLength)
	})
	APIKey("api_key", "API-Key", String)
	Required("resetCode", "userID", "newPassword")
})
