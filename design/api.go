package design

import (
	. "goa.design/goa/v3/dsl"
	cors "goa.design/plugins/v3/cors/dsl"
)

var _ = API("user", func() {
	Title("Users and authentication")
	Description("A service that manages users and authentication to various services")
	Server("auth", func() {
		Host("localhost:8080", func() {
			URI("http://localhost:8080/api")
		})
	})

	cors.Origin("*", func() {
		cors.Headers("*")
		cors.Methods("GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS")
		cors.Expose("Authorization", "X-Session")
	})
})
