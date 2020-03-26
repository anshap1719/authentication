package types

import (
	. "goa.design/goa/v3/dsl"
)

const (
	minNameLength = 2
	maxNameLength = 50
)

var UserMedia = ResultType("user-media", func() {
	Description("A user in the system")
	ContentType("application/json")
	Attributes(func() {
		Attribute("id", String, "Unique unchanging user ID")
		Attribute("firstName", String, "Given name for the user", func() {
			Example("Jeff")
		})
		Attribute("lastName", String, "Family name for the user", func() {
			Example("Newmann")
		})
		Attribute("email", String, "Email attached to the account of the user")
		Attribute("phone", String, "Phone Number Of the user")
		Attribute("changingEmail", String, "When the user attempts to change their email, this is what they will change it to after they verify that it belongs to them")
		Attribute("verifiedEmail", Boolean, "Whether the user has verified their email")
		Attribute("isAdmin", Boolean, "Whether the user is an administrator on the site")
		Attribute("updatedAt", String, func() {
			Format(FormatDateTime)
		})
		Attribute("isActive", Boolean)
		Attribute("createdAt", String, func() {
			Format(FormatDateTime)
		})
		Attribute("countryPhoneCode", String)
		Attribute("Authorization", String)
		Attribute("X-Session", String)

		Required("id", "email", "phone", "verifiedEmail", "firstName", "lastName", "Authorization", "X-Session")
	})
	View("default", func() {
		Attribute("id")
		Attribute("phone")
		Attribute("lastName")
		Attribute("updatedAt")
		Attribute("email")
		Attribute("createdAt")
		Attribute("firstName")
		Attribute("countryPhoneCode")
		Attribute("changingEmail")
		Attribute("isAdmin")
		Attribute("verifiedEmail")
		Attribute("Authorization")
		Attribute("X-Session")
	})
})

var AuthMedia = ResultType("auth-status-media", func() {
	Description("If other Oauths or Auths exists on account.")
	ContentType("application/json")
	Attributes(func() {
		Attribute("google", Boolean, "True if user has google Oauth signin")
		Attribute("facebook", Boolean, "True if user has facebook Oauth signin")
		Attribute("twitter", Boolean, "True if user has twitter Oauth signin")
		Attribute("linkedin", Boolean, "True if user has linkedin Oauth signin")
		Attribute("instagram", Boolean, "True if user has microsoft Oauth signin")
		Attribute("standard", Boolean, "True if user has password signin")
		Required("google", "facebook", "twitter", "linkedin", "instagram", "standard")
	})
	View("default", func() {
		Attribute("google")
		Attribute("facebook")
		Attribute("twitter")
		Attribute("linkedin")
		Attribute("instagram")
		Attribute("standard")
	})
})

var UserUpdateParams = Type("user-update-params", func() {
	Attribute("firstName", String, "Given name for the user", func() {
		Example("Jeff")
	})
	Attribute("lastName", String, "Family name for the user", func() {
		Example("Newmann")
	})
	Attribute("email", String, "Email attached to the account of the user")
	Attribute("phone", String, "Phone Number Of the user")
	Attribute("changingEmail", String, "When the user attempts to change their email, this is what they will change it to after they verify that it belongs to them")
	Attribute("verifiedEmail", Boolean, "Whether the user has verified their email")
	Attribute("isAdmin", Boolean, "Whether the user is an administrator on the site")
	Attribute("countryPhoneCode", String)
	Token("Authorization")
	Token("X-Session")
	APIKey("api_key", "API-Key", String)
})
