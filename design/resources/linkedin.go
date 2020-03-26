package resources

import (
	"github.com/anshap1719/authentication/design/types"
	. "goa.design/goa/v3/dsl"
)

var _ = Service("linkedin", func() {
	HTTP(func() {
		Path("/linkedin")
	})

	Method("register-url", func() {
		Security(APIKeyAuth)
		Description("Gets the URL the front-end should redirect the browser to in order to be authenticated with Linkedin, and then register")
		HTTP(func() {
			GET("/register-start")

			Headers(func() {
				Header("API-Key")
			})
		})

		Payload(func() {
			APIKey("api_key", "API-Key", String)
		})

		Result(String)
		Error("InternalServerError")
	})

	Method("attach-to-account", func() {
		Description("Attaches a Linkedin account to an existing user account, returns the URL the browser should be redirected to")
		HTTP(func() {
			POST("/attach")
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

		Result(String)
		Error("InternalServerError")
	})

	Method("detach-from-account", func() {
		Description("Detaches a Linkedin account from an existing user account.")
		HTTP(func() {
			POST("/detach")
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

	Method("receive", func() {
		Description("The endpoint that Linkedin redirects the browser to after the user has authenticated")
		HTTP(func() {
			GET("/receive")
			Headers(func() {
				Header("Authorization")
				Header("X-Session")
				Header("RedirectURL")

				Header("API-Key")
			})
			Params(func() {
				Param("code", String)
				Param("state", String, func() {
					Format(FormatUUID)
				})
				Required("code", "state")
			})

			Response(func() {
				Headers(func() {
					Header("Authorization")
					Header("X-Session")
				})
			})
		})

		Payload(func() {
			Attribute("code", String)
			Attribute("state", String, func() {
				Format(FormatUUID)
			})

			Token("Authorization")
			Token("X-Session")
			APIKey("api_key", "API-Key", String)
			Attribute("RedirectURL")
		})

		Result(types.UserMedia)
		Error("Unauthorized")
		Error("BadRequest")
		Error("InternalServerError")
	})
})
