package types

import (
	. "goa.design/goa/v3/dsl"
)

var SessionMedia = ResultType("session", func() {
	Description("A session for a user, associated with a specific browser")
	Attributes(func() {
		Attribute("id", String, "Unique unchanging session ID")
		Attribute("userId", String, "ID of the user this session is for")
		Attribute("lastUsed", String, "Time that this session was last used", func() {
			Format(FormatDateTime)
		})
		Attribute("browser", String, "The browser and browser version connected with this session")
		Attribute("os", String, "The OS of the system where this session was used")
		Attribute("ip", String, "The last IP address where this session was used")
		Attribute("location", String, "A humanReadable string describing the last known location of the session")
		Attribute("latitude", String, "The latitude of the last known location of the session")
		Attribute("longitude", String, "The longitude of the last known location of the session")
		Attribute("isMobile", Boolean, "Whether the session was from a mobile device")
		Attribute("mapUrl", String, "The URL of the Google map to show the location, suitable for using in an img tag")
		Required("id", "userId", "lastUsed", "browser", "os", "ip", "location", "latitude", "longitude", "isMobile", "mapUrl")
	})

	View("default", func() {
		Attribute("id")
		Attribute("userId")
		Attribute("lastUsed")
		Attribute("browser")
		Attribute("os")
		Attribute("ip")
		Attribute("location")
		Attribute("latitude")
		Attribute("longitude")
		Attribute("isMobile")
		Attribute("mapUrl")
	})
})

var AllSessionsMedia = ResultType("all-sessions", func() {
	Description("All of the sessions associated with a user")
	Attributes(func() {
		Attribute("currentSession", SessionMedia)
		Attribute("otherSessions", CollectionOf(SessionMedia))
	})

	View("default", func() {
		Attribute("currentSession")
		Attribute("otherSessions")
	})
})
