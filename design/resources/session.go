package resources

import (
	"github.com/anshap1719/authentication/design/types"
	. "goa.design/goa/v3/dsl"
)

var _ = Service("session", func() {
	HTTP(func() {
		Path("/auth")
	})

	Method("refresh", func() {
		Description("Take a user's session token and refresh it, also returns a new authentication token")

		Security(APIKeyAuth)

		HTTP(func() {
			POST("/session")
			Headers(func() {
				Header("X-Session", String)
				Header("API-Key")
				Required("X-Session")
			})

			Response(StatusOK, func() {
				Headers(func() {
					Header("Authorization")
					Header("X-Session")
					Required("Authorization", "X-Session")
				})
			})

			Headers(func() {

			})
		})

		Payload(func() {
			Attribute("X-Session", String)

			APIKey("api_key", "API-Key", String)
		})

		Result(func() {
			Attribute("Authorization", String)
			Attribute("X-Session", String)
		})

		Error("Unauthorized")
		Error("BadRequest")
		Error("InternalServerError")
	})

	Method("logout", func() {
		Security(JWTSec, APIKeyAuth)
		Description("Takes a user's auth token, and logs-out the session associated with it")
		HTTP(func() {
			POST("/logout")

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
		Error("InternalServerError")
	})

	Method("logout-other", func() {
		Security(JWTSec, APIKeyAuth)
		Description("Logout all sessions for the current user except their current session")
		HTTP(func() {
			POST("/logout/all")
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
		Error("InternalServerError")
	})

	Method("logout-specific", func() {
		Security(JWTSec, APIKeyAuth)
		Description("Logout of a specific session")

		HTTP(func() {
			POST("/logout/:session-id")
			Params(func() {
				Param("session-id", String)
				Required("session-id")
			})
			Headers(func() {
				Header("Authorization")
				Header("X-Session")
				Header("API-Key")
			})
		})

		Payload(func() {
			Attribute("session-id", String)
			Token("Authorization")
			Token("X-Session")
			APIKey("api_key", "API-Key", String)
		})

		Result(Empty)
		Error("BadRequest")
		Error("NotFound")
		Error("InternalServerError")
	})

	Method("get-sessions", func() {
		Security(JWTSec, APIKeyAuth)
		Description("Gets all of the sessions that are associated with the currently logged in user")
		HTTP(func() {
			GET("/sessions")

			Headers(func() {
				Header("Authorization")
				Header("X-Session")
				Header("API-Key")
			})

			Response(StatusOK)
		})

		Payload(func() {
			Token("Authorization")
			Token("X-Session")
			APIKey("api_key", "API-Key", String)
		})

		Result(types.AllSessionsMedia)
		Error("InternalServerError")
	})

	Method("redeemToken", func() {
		Description("Redeems a login token for credentials")
		Security(APIKeyAuth)
		HTTP(func() {
			POST("/token")
			Response(StatusCreated, func() {
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

		Payload(func() {
			Attribute("token", String, "A merge token for merging into an account", func() {
				Format(FormatUUID)
			})
			Attribute("User-Agent")
			APIKey("api_key", "API-Key", String)
			Required("token")
		})

		Result(func() {
			Attribute("Authorization")
			Attribute("X-Session")
		})

		Error("Forbidden")
		Error("InternalServerError")
	})

	Method("clean-sessions", func() {
		Description("Deletes all the sessions that have expired")
		Security(JWTSec, APIKeyAuth)
		HTTP(func() {
			GET("/clean/sessions")
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
		Error("Forbidden")
	})
	Method("clean-login-token", func() {
		Description("Cleans old login tokens from the database")
		Security(JWTSec, APIKeyAuth)
		HTTP(func() {
			GET("/clean/token/login")
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
		Error("Forbidden")
	})
	Method("clean-merge-token", func() {
		Description("Cleans old account merge tokens from the database")
		Security(JWTSec, APIKeyAuth)
		HTTP(func() {
			GET("/clean/token/merge")
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
		Error("Forbidden")
	})
})
