package resources

import (
	"github.com/anshap1719/authentication/design/types"
	. "goa.design/goa/v3/dsl"
)

var _ = Service("instagram", func() {
	HTTP(func() {
		Path("/instagram")
	})

	Method("register-url", func() {
		Security(APIKeyAuth)
		Description("Gets the URL the front-end should redirect the browser to in order to be authenticated with Instagram, and then register")
		HTTP(func() {
			GET("/register-start")

			Headers(func() {
				Header("API-Key")
				Header("RedirectURL")
			})
		})

		Payload(func() {
			APIKey("api_key", "API-Key", String)
			Attribute("RedirectURL", String)
		})

		Result(String)
		Error("InternalServerError")
	})

	Method("attach-to-account", func() {
		Description("Attaches a Instagram account to an existing user account, returns the URL the browser should be redirected to")
		HTTP(func() {
			POST("/attach")
			Headers(func() {
				Header("Authorization")
				Header("X-Session")
				Header("API-Key")
				Header("RedirectURL")
			})
		})
		Security(JWTSec, APIKeyAuth)

		Payload(func() {
			Token("Authorization")
			Token("X-Session")
			APIKey("api_key", "API-Key", String)
			Attribute("RedirectURL", String)
		})

		Result(String)
		Error("InternalServerError")
	})

	Method("detach-from-account", func() {
		Description("Detaches a Instagram account from an existing user account.")
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
		Description("The endpoint that Instagram redirects the browser to after the user has authenticated")
		HTTP(func() {
			GET("/receive")
			Params(func() {
				Param("code", String)
				Param("state", String, func() {
					Format(FormatUUID)
				})
				Required("code", "state")
			})

			Headers(func() {
				Header("Authorization")
				Header("X-Session")
				Header("RedirectURL")

				Header("API-Key")
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
			Attribute("RedirectURL", String)
		})

		Result(types.UserMedia)

		Error("Unauthorized")
		Error("BadRequest")
		Error("InternalServerError")
	})
})
