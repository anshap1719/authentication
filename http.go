package main

import (
	"context"
	"github.com/NYTimes/gziphandler"
	"github.com/anshap1719/authentication/controllers/gen/facebook"
	"github.com/anshap1719/authentication/controllers/gen/google"
	facebooksvr "github.com/anshap1719/authentication/controllers/gen/http/facebook/server"
	googlesvr "github.com/anshap1719/authentication/controllers/gen/http/google/server"
	instagramsvr "github.com/anshap1719/authentication/controllers/gen/http/instagram/server"
	linkedinsvr "github.com/anshap1719/authentication/controllers/gen/http/linkedin/server"
	monitoringsvr "github.com/anshap1719/authentication/controllers/gen/http/monitoring/server"
	passwordauthsvr "github.com/anshap1719/authentication/controllers/gen/http/password_auth/server"
	sessionsvr "github.com/anshap1719/authentication/controllers/gen/http/session/server"
	twittersvr "github.com/anshap1719/authentication/controllers/gen/http/twitter/server"
	usersvr "github.com/anshap1719/authentication/controllers/gen/http/user/server"
	"github.com/anshap1719/authentication/controllers/gen/instagram"
	"github.com/anshap1719/authentication/controllers/gen/linkedin"
	"github.com/anshap1719/authentication/controllers/gen/monitoring"
	passwordauth "github.com/anshap1719/authentication/controllers/gen/password_auth"
	"github.com/anshap1719/authentication/controllers/gen/session"
	"github.com/anshap1719/authentication/controllers/gen/twitter"
	"github.com/anshap1719/authentication/controllers/gen/user"
	"github.com/anshap1719/authentication/utils/ctx"
	"github.com/anshap1719/authentication/utils/database"
	"github.com/anshap1719/authentication/utils/limiter"
	goahttp "goa.design/goa/v3/http"
	httpmdlwr "goa.design/goa/v3/http/middleware"
	"goa.design/goa/v3/middleware"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// handleHTTPServer starts configures and starts a HTTP server on the given
// URL. It shuts down the server if any error is received in the error channel.
func handleHTTPServer(cntxt context.Context, facebookEndpoints *facebook.Endpoints, googleEndpoints *google.Endpoints, instagramEndpoints *instagram.Endpoints, linkedinEndpoints *linkedin.Endpoints, passwordAuthEndpoints *passwordauth.Endpoints, sessionEndpoints *session.Endpoints, twitterEndpoints *twitter.Endpoints, userEndpoints *user.Endpoints, monitoringEndpoints *monitoring.Endpoints, wg *sync.WaitGroup, errc chan error) {
	var logger *log.Logger

	logger = log.New(os.Stderr, "[authentication] ", log.Ltime)

	// Setup goa log adapter.
	var (
		adapter middleware.Logger
	)
	{
		adapter = middleware.NewLogger(logger)
	}

	// Provide the transport specific request decoder and response encoder.
	// The goa http package has built-in support for JSON, XML and gob.
	// Other encodings can be used by providing the corresponding functions,
	// see goa.design/implement/encoding.
	var (
		dec = goahttp.RequestDecoder
		enc = goahttp.ResponseEncoder
	)

	// Build the service HTTP request multiplexer and configure it to serve
	// HTTP requests to the service endpoints.
	var mux goahttp.Muxer
	{
		mux = goahttp.NewMuxer()
	}

	// Wrap the endpoints with the transport specific layers. The generated
	// server packages contains code generated from the design which maps
	// the service input and output data structures to HTTP requests and
	// responses.
	var (
		facebookServer     *facebooksvr.Server
		googleServer       *googlesvr.Server
		instagramServer    *instagramsvr.Server
		linkedinServer     *linkedinsvr.Server
		passwordAuthServer *passwordauthsvr.Server
		sessionServer      *sessionsvr.Server
		twitterServer      *twittersvr.Server
		userServer         *usersvr.Server
		monitoringServer   *monitoringsvr.Server
	)
	{
		eh := errorHandler(logger)
		facebookServer = facebooksvr.New(facebookEndpoints, mux, dec, enc, eh)
		googleServer = googlesvr.New(googleEndpoints, mux, dec, enc, eh)
		instagramServer = instagramsvr.New(instagramEndpoints, mux, dec, enc, eh)
		linkedinServer = linkedinsvr.New(linkedinEndpoints, mux, dec, enc, eh)
		passwordAuthServer = passwordauthsvr.New(passwordAuthEndpoints, mux, dec, enc, eh)
		sessionServer = sessionsvr.New(sessionEndpoints, mux, dec, enc, eh)
		twitterServer = twittersvr.New(twitterEndpoints, mux, dec, enc, eh)
		userServer = usersvr.New(userEndpoints, mux, dec, enc, eh)
		monitoringServer = monitoringsvr.New(monitoringEndpoints, mux, dec, enc, eh)
	}

	facebookServer.Use(ctx.PopulateRequestContext())
	googleServer.Use(ctx.PopulateRequestContext())
	instagramServer.Use(ctx.PopulateRequestContext())
	linkedinServer.Use(ctx.PopulateRequestContext())
	passwordAuthServer.Use(ctx.PopulateRequestContext())
	sessionServer.Use(ctx.PopulateRequestContext())
	twitterServer.Use(ctx.PopulateRequestContext())
	userServer.Use(ctx.PopulateRequestContext())
	monitoringServer.Use(ctx.PopulateRequestContext())

	facebookServer.Use(limiter.RateLimitSocialServices())
	googleServer.Use(limiter.RateLimitSocialServices())
	instagramServer.Use(limiter.RateLimitSocialServices())
	linkedinServer.Use(limiter.RateLimitSocialServices())
	passwordAuthServer.Use(limiter.RateLimitMainServices())
	sessionServer.Use(limiter.RateLimitMainServices())
	twitterServer.Use(limiter.RateLimitSocialServices())
	userServer.Use(limiter.RateLimitMainServices())

	// Configure the mux.
	facebooksvr.Mount(mux, facebookServer)
	googlesvr.Mount(mux, googleServer)
	instagramsvr.Mount(mux, instagramServer)
	linkedinsvr.Mount(mux, linkedinServer)
	passwordauthsvr.Mount(mux, passwordAuthServer)
	sessionsvr.Mount(mux, sessionServer)
	twittersvr.Mount(mux, twitterServer)
	usersvr.Mount(mux, userServer)
	monitoringsvr.Mount(mux, monitoringServer)

	// Wrap the multiplexer with additional middlewares. Middlewares mounted
	// here apply to all the service endpoints.
	var handler http.Handler = mux
	{

		handler = httpmdlwr.RequestID()(handler)
		handler = httpmdlwr.Log(adapter)(handler)
	}

	// Start HTTP server using default configuration, change the code to
	// configure the server as required by your service.
	srv := &http.Server{Addr: ":" + os.Getenv("PORT"), Handler: gziphandler.GzipHandler(handler)}
	for _, m := range facebookServer.Mounts {
		logger.Printf("HTTP %q mounted on %s %s", m.Method, m.Verb, m.Pattern)
	}
	for _, m := range googleServer.Mounts {
		logger.Printf("HTTP %q mounted on %s %s", m.Method, m.Verb, m.Pattern)
	}
	for _, m := range instagramServer.Mounts {
		logger.Printf("HTTP %q mounted on %s %s", m.Method, m.Verb, m.Pattern)
	}
	for _, m := range linkedinServer.Mounts {
		logger.Printf("HTTP %q mounted on %s %s", m.Method, m.Verb, m.Pattern)
	}
	for _, m := range passwordAuthServer.Mounts {
		logger.Printf("HTTP %q mounted on %s %s", m.Method, m.Verb, m.Pattern)
	}
	for _, m := range sessionServer.Mounts {
		logger.Printf("HTTP %q mounted on %s %s", m.Method, m.Verb, m.Pattern)
	}
	for _, m := range twitterServer.Mounts {
		logger.Printf("HTTP %q mounted on %s %s", m.Method, m.Verb, m.Pattern)
	}
	for _, m := range userServer.Mounts {
		logger.Printf("HTTP %q mounted on %s %s", m.Method, m.Verb, m.Pattern)
	}
	for _, m := range monitoringServer.Mounts {
		logger.Printf("HTTP %q mounted on %s %s", m.Method, m.Verb, m.Pattern)
	}

	(*wg).Add(1)
	go func() {
		defer (*wg).Done()

		// Start HTTP server in a separate goroutine.
		go func() {
			logger.Printf("HTTP server started")
			errc <- srv.ListenAndServe()
		}()

		<-cntxt.Done()
		database.CloseConnection()
		logger.Printf("shutting down HTTP server")

		// Shutdown gracefully with a 30s timeout.
		goactx, cancel := context.WithTimeout(cntxt, 30*time.Second)
		defer cancel()

		srv.Shutdown(goactx)
	}()
}

// errorHandler returns a function that writes and logs the given error.
// The function also writes and logs the error unique ID so that it's possible
// to correlate.
func errorHandler(logger *log.Logger) func(context.Context, http.ResponseWriter, error) {
	return func(ctx context.Context, w http.ResponseWriter, err error) {
		id := ctx.Value(middleware.RequestIDKey).(string)
		w.Write([]byte("[" + id + "] encoding: " + err.Error()))
		reqID := ctx.Value(middleware.RequestIDKey).(string)

		logger.Printf("[%s] ERROR: %s", reqID, err.Error())
	}
}
