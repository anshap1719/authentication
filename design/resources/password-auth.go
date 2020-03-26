package resources

import (
	"github.com/anshap1719/authentication/design/types"
	. "goa.design/goa/v3/dsl"
)

var _ = Service("password-auth", func() {
	HTTP(func() {
		Path("/")
	})
	Method("register", func() {
		Security(APIKeyAuth)
		Description("Register a new user with an email and password")

		HTTP(func() {
			POST("/register")
			Response(StatusOK, func() {
				Headers(func() {
					Header("Authorization")
					Header("X-Session")
					Required("Authorization", "X-Session")
				})
			})
			Headers(func() {
				Header("Authorization")
				Header("X-Session")

				Header("API-Key")
			})
		})

		Payload(types.RegisterParams)

		Result(types.UserMedia)

		Error("BadRequest")
		Error("Forbidden")
		Error("InternalServerError")
	})

	Method("login", func() {
		Security(APIKeyAuth)
		Description("Login a user using an email and password")
		HTTP(func() {
			POST("/login")

			Params(func() {
				Param("token", String, "A merge token for merging into an account", func() {
					Format(FormatUUID)
				})
			})
			Response(StatusOK, func() {
				Headers(func() {
					Header("Authorization")
					Header("X-Session")
					Required("Authorization", "X-Session")
				})
			})

			Headers(func() {

				Header("API-Key")
			})
		})

		Payload(types.LoginParams)

		Result(types.UserMedia)

		Error("Unauthorized")
		Error("BadRequest")
		Error("InternalServerError")
	})

	Method("remove", func() {
		Description("Removes using a password as a login method")
		HTTP(func() {
			POST("/remove-password")

			Headers(func() {
				Header("Authorization")
				Header("X-Session")
				Header("API-Key")
			})
		})
		Security(JWTSec, APIKeyAuth)

		Payload(func() {
			Token("Authorization")
			Token("X-Session")
			APIKey("api_key", "API-Key", String)
		})

		Result(Empty)
		Error("NotFound")
		Error("Forbidden")
		Error("InternalServerError")
	})

	Method("change-password", func() {
		Description("Changes the user's current password to a new one, also adds a password to the account if there is none")
		HTTP(func() {
			POST("/change-password")
			Headers(func() {
				Header("Authorization")
				Header("X-Session")
				Header("API-Key")
			})
		})
		Security(JWTSec, APIKeyAuth)
		Payload(types.ChangePasswordParams)

		Result(Empty)
		Error("BadRequest")
		Error("InternalServerError")
	})

	Method("reset", func() {
		Security(APIKeyAuth)
		Description("Send an email to user to get a password reset, responds with no content even if the email is not on any user account")
		HTTP(func() {
			POST("/reset-password")

			Params(func() {
				Param("email", String, "Email of the account to send a password reset", func() {
					Format("email")
				})
				Required("email", "redirect-url")
			})

			Headers(func() {
				Header("API-Key")
			})
		})

		Payload(func() {
			Attribute("email")
			APIKey("api_key", "API-Key", String)
		})

		Result(Empty)
		Error("InternalServerError")
	})

	Method("confirm-reset", func() {
		Security(APIKeyAuth)
		Description("Confirms that a reset has been completed and changes the password to the new one passed in")
		HTTP(func() {
			POST("/finalize-reset")

			Headers(func() {
				Header("API-Key")
			})
		})
		Payload(types.ResetPasswordParams)
		Result(Empty)
		Error("Forbidden")
		Error("InternalServerError")
	})

	Method("check-email-available", func() {
		Security(APIKeyAuth)
		Description("Checks if an email is available for signup")
		HTTP(func() {
			POST("/check-email-available")

			Params(func() {
				Param("email", String)
			})

			Headers(func() {
				Header("API-Key")
			})
		})

		Payload(func() {
			Attribute("email", String)
			APIKey("api_key", "API-Key", String)
		})

		Result(Boolean)

		Error("InternalServerError")
	})

	Method("check-phone-available", func() {
		Security(APIKeyAuth)
		Description("Checks if an phone is available for signup")
		HTTP(func() {
			POST("/check-phone-available")

			Params(func() {
				Param("phone", String)
			})

			Headers(func() {
				Header("API-Key")
			})
		})

		Payload(func() {
			Attribute("phone", String)
			APIKey("api_key", "API-Key", String)
		})

		Result(Boolean)

		Error("InternalServerError")
	})
})
