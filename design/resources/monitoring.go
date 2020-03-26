package resources

import (
	. "goa.design/goa/v3/dsl"
)

var _ = Service("monitoring", func() {
	HTTP(func() {
		Path("/monitoring")
	})

	Method("status", func() {
		HTTP(func() {
			GET("/status")
		})

		Error("InternalServerError")
	})
})
