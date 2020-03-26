package resources

import (
	. "goa.design/goa/v3/dsl"
)

var JWTSec = JWTSecurity("jwt", func() {
	Description("JWT Authentication Security")
})

var APIKeyAuth = APIKeySecurity("api_key", func() {
	Description("API Key for users API")
})
