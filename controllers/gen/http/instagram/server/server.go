// Code generated by goa v3.0.6, DO NOT EDIT.
//
// instagram HTTP server
//
// Command:
// $ goa gen github.com/anshap1719/authentication/design

package server

import (
	"context"
	"net/http"

	instagram "github.com/anshap1719/authentication/controllers/gen/instagram"
	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
	"goa.design/plugins/v3/cors"
)

// Server lists the instagram service endpoint HTTP handlers.
type Server struct {
	Mounts            []*MountPoint
	RegisterURL       http.Handler
	AttachToAccount   http.Handler
	DetachFromAccount http.Handler
	Receive           http.Handler
	CORS              http.Handler
}

// ErrorNamer is an interface implemented by generated error structs that
// exposes the name of the error as defined in the design.
type ErrorNamer interface {
	ErrorName() string
}

// MountPoint holds information about the mounted endpoints.
type MountPoint struct {
	// Method is the name of the service method served by the mounted HTTP handler.
	Method string
	// Verb is the HTTP method used to match requests to the mounted handler.
	Verb string
	// Pattern is the HTTP request path pattern used to match requests to the
	// mounted handler.
	Pattern string
}

// New instantiates HTTP handlers for all the instagram service endpoints.
func New(
	e *instagram.Endpoints,
	mux goahttp.Muxer,
	dec func(*http.Request) goahttp.Decoder,
	enc func(context.Context, http.ResponseWriter) goahttp.Encoder,
	eh func(context.Context, http.ResponseWriter, error),
) *Server {
	return &Server{
		Mounts: []*MountPoint{
			{"RegisterURL", "GET", "/instagram/register-start"},
			{"AttachToAccount", "POST", "/instagram/attach"},
			{"DetachFromAccount", "POST", "/instagram/detach"},
			{"Receive", "GET", "/instagram/receive"},
			{"CORS", "OPTIONS", "/instagram/register-start"},
			{"CORS", "OPTIONS", "/instagram/attach"},
			{"CORS", "OPTIONS", "/instagram/detach"},
			{"CORS", "OPTIONS", "/instagram/receive"},
		},
		RegisterURL:       NewRegisterURLHandler(e.RegisterURL, mux, dec, enc, eh),
		AttachToAccount:   NewAttachToAccountHandler(e.AttachToAccount, mux, dec, enc, eh),
		DetachFromAccount: NewDetachFromAccountHandler(e.DetachFromAccount, mux, dec, enc, eh),
		Receive:           NewReceiveHandler(e.Receive, mux, dec, enc, eh),
		CORS:              NewCORSHandler(),
	}
}

// Service returns the name of the service served.
func (s *Server) Service() string { return "instagram" }

// Use wraps the server handlers with the given middleware.
func (s *Server) Use(m func(http.Handler) http.Handler) {
	s.RegisterURL = m(s.RegisterURL)
	s.AttachToAccount = m(s.AttachToAccount)
	s.DetachFromAccount = m(s.DetachFromAccount)
	s.Receive = m(s.Receive)
	s.CORS = m(s.CORS)
}

// Mount configures the mux to serve the instagram endpoints.
func Mount(mux goahttp.Muxer, h *Server) {
	MountRegisterURLHandler(mux, h.RegisterURL)
	MountAttachToAccountHandler(mux, h.AttachToAccount)
	MountDetachFromAccountHandler(mux, h.DetachFromAccount)
	MountReceiveHandler(mux, h.Receive)
	MountCORSHandler(mux, h.CORS)
}

// MountRegisterURLHandler configures the mux to serve the "instagram" service
// "register-url" endpoint.
func MountRegisterURLHandler(mux goahttp.Muxer, h http.Handler) {
	f, ok := handleInstagramOrigin(h).(http.HandlerFunc)
	if !ok {
		f = func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
		}
	}
	mux.Handle("GET", "/instagram/register-start", f)
}

// NewRegisterURLHandler creates a HTTP handler which loads the HTTP request
// and calls the "instagram" service "register-url" endpoint.
func NewRegisterURLHandler(
	endpoint goa.Endpoint,
	mux goahttp.Muxer,
	dec func(*http.Request) goahttp.Decoder,
	enc func(context.Context, http.ResponseWriter) goahttp.Encoder,
	eh func(context.Context, http.ResponseWriter, error),
) http.Handler {
	var (
		decodeRequest  = DecodeRegisterURLRequest(mux, dec)
		encodeResponse = EncodeRegisterURLResponse(enc)
		encodeError    = goahttp.ErrorEncoder(enc)
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), goahttp.AcceptTypeKey, r.Header.Get("Accept"))
		ctx = context.WithValue(ctx, goa.MethodKey, "register-url")
		ctx = context.WithValue(ctx, goa.ServiceKey, "instagram")
		payload, err := decodeRequest(r)
		if err != nil {
			if err := encodeError(ctx, w, err); err != nil {
				eh(ctx, w, err)
			}
			return
		}

		res, err := endpoint(ctx, payload)

		if err != nil {
			if err := encodeError(ctx, w, err); err != nil {
				eh(ctx, w, err)
			}
			return
		}
		if err := encodeResponse(ctx, w, res); err != nil {
			eh(ctx, w, err)
		}
	})
}

// MountAttachToAccountHandler configures the mux to serve the "instagram"
// service "attach-to-account" endpoint.
func MountAttachToAccountHandler(mux goahttp.Muxer, h http.Handler) {
	f, ok := handleInstagramOrigin(h).(http.HandlerFunc)
	if !ok {
		f = func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
		}
	}
	mux.Handle("POST", "/instagram/attach", f)
}

// NewAttachToAccountHandler creates a HTTP handler which loads the HTTP
// request and calls the "instagram" service "attach-to-account" endpoint.
func NewAttachToAccountHandler(
	endpoint goa.Endpoint,
	mux goahttp.Muxer,
	dec func(*http.Request) goahttp.Decoder,
	enc func(context.Context, http.ResponseWriter) goahttp.Encoder,
	eh func(context.Context, http.ResponseWriter, error),
) http.Handler {
	var (
		decodeRequest  = DecodeAttachToAccountRequest(mux, dec)
		encodeResponse = EncodeAttachToAccountResponse(enc)
		encodeError    = goahttp.ErrorEncoder(enc)
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), goahttp.AcceptTypeKey, r.Header.Get("Accept"))
		ctx = context.WithValue(ctx, goa.MethodKey, "attach-to-account")
		ctx = context.WithValue(ctx, goa.ServiceKey, "instagram")
		payload, err := decodeRequest(r)
		if err != nil {
			if err := encodeError(ctx, w, err); err != nil {
				eh(ctx, w, err)
			}
			return
		}

		res, err := endpoint(ctx, payload)

		if err != nil {
			if err := encodeError(ctx, w, err); err != nil {
				eh(ctx, w, err)
			}
			return
		}
		if err := encodeResponse(ctx, w, res); err != nil {
			eh(ctx, w, err)
		}
	})
}

// MountDetachFromAccountHandler configures the mux to serve the "instagram"
// service "detach-from-account" endpoint.
func MountDetachFromAccountHandler(mux goahttp.Muxer, h http.Handler) {
	f, ok := handleInstagramOrigin(h).(http.HandlerFunc)
	if !ok {
		f = func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
		}
	}
	mux.Handle("POST", "/instagram/detach", f)
}

// NewDetachFromAccountHandler creates a HTTP handler which loads the HTTP
// request and calls the "instagram" service "detach-from-account" endpoint.
func NewDetachFromAccountHandler(
	endpoint goa.Endpoint,
	mux goahttp.Muxer,
	dec func(*http.Request) goahttp.Decoder,
	enc func(context.Context, http.ResponseWriter) goahttp.Encoder,
	eh func(context.Context, http.ResponseWriter, error),
) http.Handler {
	var (
		decodeRequest  = DecodeDetachFromAccountRequest(mux, dec)
		encodeResponse = EncodeDetachFromAccountResponse(enc)
		encodeError    = goahttp.ErrorEncoder(enc)
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), goahttp.AcceptTypeKey, r.Header.Get("Accept"))
		ctx = context.WithValue(ctx, goa.MethodKey, "detach-from-account")
		ctx = context.WithValue(ctx, goa.ServiceKey, "instagram")
		payload, err := decodeRequest(r)
		if err != nil {
			if err := encodeError(ctx, w, err); err != nil {
				eh(ctx, w, err)
			}
			return
		}

		res, err := endpoint(ctx, payload)

		if err != nil {
			if err := encodeError(ctx, w, err); err != nil {
				eh(ctx, w, err)
			}
			return
		}
		if err := encodeResponse(ctx, w, res); err != nil {
			eh(ctx, w, err)
		}
	})
}

// MountReceiveHandler configures the mux to serve the "instagram" service
// "receive" endpoint.
func MountReceiveHandler(mux goahttp.Muxer, h http.Handler) {
	f, ok := handleInstagramOrigin(h).(http.HandlerFunc)
	if !ok {
		f = func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
		}
	}
	mux.Handle("GET", "/instagram/receive", f)
}

// NewReceiveHandler creates a HTTP handler which loads the HTTP request and
// calls the "instagram" service "receive" endpoint.
func NewReceiveHandler(
	endpoint goa.Endpoint,
	mux goahttp.Muxer,
	dec func(*http.Request) goahttp.Decoder,
	enc func(context.Context, http.ResponseWriter) goahttp.Encoder,
	eh func(context.Context, http.ResponseWriter, error),
) http.Handler {
	var (
		decodeRequest  = DecodeReceiveRequest(mux, dec)
		encodeResponse = EncodeReceiveResponse(enc)
		encodeError    = goahttp.ErrorEncoder(enc)
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), goahttp.AcceptTypeKey, r.Header.Get("Accept"))
		ctx = context.WithValue(ctx, goa.MethodKey, "receive")
		ctx = context.WithValue(ctx, goa.ServiceKey, "instagram")
		payload, err := decodeRequest(r)
		if err != nil {
			if err := encodeError(ctx, w, err); err != nil {
				eh(ctx, w, err)
			}
			return
		}

		res, err := endpoint(ctx, payload)

		if err != nil {
			if err := encodeError(ctx, w, err); err != nil {
				eh(ctx, w, err)
			}
			return
		}
		if err := encodeResponse(ctx, w, res); err != nil {
			eh(ctx, w, err)
		}
	})
}

// MountCORSHandler configures the mux to serve the CORS endpoints for the
// service instagram.
func MountCORSHandler(mux goahttp.Muxer, h http.Handler) {
	h = handleInstagramOrigin(h)
	f, ok := h.(http.HandlerFunc)
	if !ok {
		f = func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
		}
	}
	mux.Handle("OPTIONS", "/instagram/register-start", f)
	mux.Handle("OPTIONS", "/instagram/attach", f)
	mux.Handle("OPTIONS", "/instagram/detach", f)
	mux.Handle("OPTIONS", "/instagram/receive", f)
}

// NewCORSHandler creates a HTTP handler which returns a simple 200 response.
func NewCORSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
}

// handleInstagramOrigin applies the CORS response headers corresponding to the
// origin for the service instagram.
func handleInstagramOrigin(h http.Handler) http.Handler {
	origHndlr := h.(http.HandlerFunc)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			// Not a CORS request
			origHndlr(w, r)
			return
		}
		if cors.MatchOrigin(origin, "*") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Expose-Headers", "Authorization, X-Session")
			w.Header().Set("Access-Control-Allow-Credentials", "false")
			if acrm := r.Header.Get("Access-Control-Request-Method"); acrm != "" {
				// We are handling a preflight request
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "*")
			}
			origHndlr(w, r)
			return
		}
		origHndlr(w, r)
		return
	})
}
