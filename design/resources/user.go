package resources

import (
	"github.com/anshap1719/authentication/design/types"
	. "goa.design/goa/v3/dsl"
)

var _ = Service("user", func() {
	HTTP(func() {
		Path("/user")
	})

	Method("getAuths", func() {
		Security(APIKeyAuth)
		Description("Returns whether Oauth is attached or not")
		HTTP(func() {
			GET("/authstat")
			Params(func() {
				Param("userID", String, "The ID of the requested user. If this is not provide, get currently logged in user")
			})

			Response(StatusOK)

			Headers(func() {
				Header("Authorization")
				Header("X-Session")
				Header("API-Key")
			})
		})

		Payload(func() {
			Attribute("userID")
			Attribute("Authorization", String)
			Attribute("X-Session", String)
			APIKey("api_key", "API-Key", String)
		})

		Result(types.AuthMedia)

		Error("BadRequest")
		Error("Unauthorized")
		Error("InternalServerError")
	})

	Method("deactivate", func() {
		Description("Disable a user's account")

		HTTP(func() {
			DELETE("")
			Params(func() {
				Param("id", String, "id of the user to be deactivated when admin is deactivating a user")
				Param("admin", Boolean, "whether admin is requesting this deactivation")
			})
			Headers(func() {
				Header("Authorization")
				Header("X-Session")
				Header("API-Key")
			})
		})

		Payload(func() {
			Attribute("id")
			Attribute("admin")
			Token("Authorization")
			Token("X-Session")
			APIKey("api_key", "API-Key", String)
		})

		Security(JWTSec, APIKeyAuth)
		Result(Empty)
		Error("Forbidden")
		Error("InternalServerError")
	})

	Method("getUser", func() {
		Description("Get a user's details")

		HTTP(func() {
			GET("")
			Headers(func() {
				Header("Authorization")
				Header("X-Session")
				Header("API-Key")
			})
		})

		Payload(func() {
			Token("Authorization")
			Token("X-Session")
			APIKey("api_key", "API-Key", String)
		})

		Security(JWTSec, APIKeyAuth)
		Result(types.UserMedia)
		Error("Forbidden")
		Error("InternalServerError")
	})

	Method("validate-email", func() {
		Security(APIKeyAuth)
		Description("Validates an email address, designed to be called by users directly in their browser")

		HTTP(func() {
			GET("/verifyemail/{validateID}")

			Headers(func() {
				Header("API-Key")
			})
		})

		Payload(func() {
			Attribute("validateID")
			APIKey("api_key", "API-Key", String)
		})

		Result(Empty)
		Error("NotFound")
		Error("InternalServerError")
	})

	Method("update-user", func() {
		Description("Update a user")

		HTTP(func() {
			POST("")
			Headers(func() {
				Header("Authorization")
				Header("X-Session")
				Header("API-Key")
			})
		})

		Payload(types.UserUpdateParams)

		Security(JWTSec, APIKeyAuth)
		Result(types.UserMedia)
		Error("Forbidden")
		Error("InternalServerError")
	})

	Method("resend-verify-email", func() {
		Security(APIKeyAuth)
		Description("Resends a verify email for the current user, also invalidates the link on the previously send email verification")
		HTTP(func() {
			POST("/resend-verify")

			Headers(func() {
				Header("Authorization")
				Header("X-Session")
				Header("API-Key")
			})
		})

		Payload(func() {
			Attribute("Authorization", String)
			Attribute("X-Session", String)
			APIKey("api_key", "API-Key", String)
		})

		Result(Empty)
		Error("NotFound")
		Error("InternalServerError")
	})

	Method("update-phone", func() {
		Security(JWTSec, APIKeyAuth)
		Description("Update Phone and send an OTP to entered phone for verification")
		HTTP(func() {
			GET("/update-phone")
			Params(func() {
				Param("phone", String, "Phone number to be updated")
				Param("country", String, "Country code of the phone entered")
			})

			Response(StatusOK)

			Headers(func() {
				Header("Authorization")
				Header("X-Session")
				Header("API-Key")
			})
		})

		Payload(func() {
			Attribute("phone")
			Attribute("country")
			Token("Authorization")
			Token("X-Session")
			APIKey("api_key", "API-Key", String)
		})

		Result(Empty)

		Error("BadRequest")
		Error("Unauthorized")
		Error("InternalServerError")
	})

	Method("resend-otp", func() {
		Security(JWTSec, APIKeyAuth)
		Description("Resend otp for phone verification")
		HTTP(func() {
			GET("/resend-phone-otp")

			Response(StatusOK)

			Headers(func() {
				Header("Authorization")
				Header("X-Session")
				Header("API-Key")
			})
		})

		Payload(func() {
			Token("Authorization")
			Token("X-Session")
			APIKey("api_key", "API-Key", String)
		})

		Result(Empty)

		Error("BadRequest")
		Error("Unauthorized")
		Error("InternalServerError")
	})

	Method("verify-phone", func() {
		Security(JWTSec, APIKeyAuth)
		Description("Verify phone with entered phone")
		HTTP(func() {
			GET("/verify-phone-otp")
			Params(func() {
				Param("otp", String)
			})

			Response(StatusOK)

			Headers(func() {
				Header("Authorization")
				Header("X-Session")
				Header("API-Key")
			})
		})

		Payload(func() {
			Attribute("otp", String)
			Token("Authorization")
			Token("X-Session")
			APIKey("api_key", "API-Key", String)
		})

		Result(Empty)

		Error("BadRequest")
		Error("Unauthorized")
		Error("InternalServerError")
	})
})
