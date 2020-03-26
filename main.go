package main

import (
	"context"
	"fmt"
	"github.com/anshap1719/authentication/controllers"
	"github.com/anshap1719/authentication/controllers/gen/facebook"
	"github.com/anshap1719/authentication/controllers/gen/google"
	"github.com/anshap1719/authentication/controllers/gen/instagram"
	"github.com/anshap1719/authentication/controllers/gen/linkedin"
	"github.com/anshap1719/authentication/controllers/gen/monitoring"
	passwordauth "github.com/anshap1719/authentication/controllers/gen/password_auth"
	"github.com/anshap1719/authentication/controllers/gen/session"
	"github.com/anshap1719/authentication/controllers/gen/twitter"
	"github.com/anshap1719/authentication/controllers/gen/user"
	"github.com/anshap1719/authentication/models"
	"github.com/anshap1719/authentication/utils/auth"
	"github.com/anshap1719/authentication/utils/database"
	authlogs "github.com/anshap1719/authentication/utils/log"
	"github.com/joho/godotenv"
	"log"
	"os"
	"os/signal"
	"sync"
)

func main() {
	if os.Getenv("STAGE") == "DEVELOPMENT" {
		if err := godotenv.Load(); err != nil {
			panic(err)
		}
	}

	var (
		logs *log.Logger
	)

	logs = log.New(os.Stderr, "[authentication] ", log.Ltime)

	initDB()

	jwtSec, err := auth.NewJWTSecurity()
	if err != nil {
		panic("unable to create jwt security")
	}

	sessionService := controllers.NewSessionService(logs, &jwtSec)

	// Initialize the services.
	var (
		facebookSvc     facebook.Service
		googleSvc       google.Service
		instagramSvc    instagram.Service
		linkedinSvc     linkedin.Service
		passwordAuthSvc passwordauth.Service
		sessionSvc      session.Service
		twitterSvc      twitter.Service
		userSvc         user.Service
		monitoringSvc   monitoring.Service
	)
	{
		sessionSvc = sessionService
		facebookSvc = controllers.NewFacebookService(logs, &jwtSec, sessionService)
		googleSvc = controllers.NewGoogleService(logs, &jwtSec, sessionService)
		instagramSvc = controllers.NewInstagramService(logs, &jwtSec, sessionService)
		linkedinSvc = controllers.NewLinkedinService(logs, &jwtSec, sessionService)
		passwordAuthSvc = controllers.NewPasswordAuthService(logs, &jwtSec, sessionService)
		twitterSvc = controllers.NewTwitterService(logs, &jwtSec, sessionService)
		userSvc = controllers.NewUsersService(logs, &jwtSec, sessionService)
		monitoringSvc = controllers.NewMonitoring(logs)
	}

	// Wrap the services in endpoints that can be invoked from other services
	// potentially running in different processes.
	var (
		facebookEndpoints     *facebook.Endpoints
		googleEndpoints       *google.Endpoints
		instagramEndpoints    *instagram.Endpoints
		linkedinEndpoints     *linkedin.Endpoints
		passwordAuthEndpoints *passwordauth.Endpoints
		sessionEndpoints      *session.Endpoints
		twitterEndpoints      *twitter.Endpoints
		userEndpoints         *user.Endpoints
		monitoringEndpoints   *monitoring.Endpoints
	)
	{
		facebookEndpoints = facebook.NewEndpoints(facebookSvc)
		googleEndpoints = google.NewEndpoints(googleSvc)
		instagramEndpoints = instagram.NewEndpoints(instagramSvc)
		linkedinEndpoints = linkedin.NewEndpoints(linkedinSvc)
		passwordAuthEndpoints = passwordauth.NewEndpoints(passwordAuthSvc)
		sessionEndpoints = session.NewEndpoints(sessionSvc)
		twitterEndpoints = twitter.NewEndpoints(twitterSvc)
		userEndpoints = user.NewEndpoints(userSvc)
		monitoringEndpoints = monitoring.NewEndpoints(monitoringSvc)
	}

	facebookEndpoints.Use(authlogs.ErrorLogger(logs, "facebook"))
	googleEndpoints.Use(authlogs.ErrorLogger(logs, "google"))
	instagramEndpoints.Use(authlogs.ErrorLogger(logs, "instagram"))
	linkedinEndpoints.Use(authlogs.ErrorLogger(logs, "linkedin"))
	passwordAuthEndpoints.Use(authlogs.ErrorLogger(logs, "password_auth"))
	sessionEndpoints.Use(authlogs.ErrorLogger(logs, "session"))
	twitterEndpoints.Use(authlogs.ErrorLogger(logs, "twitter"))
	userEndpoints.Use(authlogs.ErrorLogger(logs, "user"))
	monitoringEndpoints.Use(authlogs.ErrorLogger(logs, "monitoring"))

	// Create channel used by both the signal handler and server goroutines
	// to notify the main goroutine when to stop the server.
	errc := make(chan error)

	// Setup interrupt handler. This optional step configures the process so
	// that SIGINT and SIGTERM signals cause the services to stop gracefully.
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		errc <- fmt.Errorf("%s", <-c)
	}()

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	handleHTTPServer(ctx, facebookEndpoints, googleEndpoints, instagramEndpoints, linkedinEndpoints, passwordAuthEndpoints, sessionEndpoints, twitterEndpoints, userEndpoints, monitoringEndpoints, &wg, errc)

	// Wait for signal.
	log.Printf("exiting (%v)", <-errc)

	// Send cancellation signal to the goroutines.
	cancel()

	wg.Wait()
	log.Println("exited")
}

func initDB() {
	if database.Database == nil {
		database.InitDB()
	}

	models.InitCollections()
}
