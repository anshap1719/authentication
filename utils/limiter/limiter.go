package limiter

import (
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/middleware/stdlib"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"log"
	"net/http"
)

var Store = memory.NewStore()

func RateLimitSocialServices() func(http.Handler) http.Handler {
	rate, err := limiter.NewRateFromFormatted("20000-H")
	if err != nil {
		log.Fatal(err)
	}

	middleware := stdlib.NewMiddleware(limiter.New(Store, rate, limiter.WithTrustForwardHeader(true)))

	return func(h http.Handler) http.Handler {
		// A HTTP handler is a function.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			middleware.Handler(h).ServeHTTP(w, r)
		})
	}
}

func RateLimitMainServices() func(http.Handler) http.Handler {
	rate, err := limiter.NewRateFromFormatted("100000-H")
	if err != nil {
		log.Fatal(err)
	}

	middleware := stdlib.NewMiddleware(limiter.New(Store, rate, limiter.WithTrustForwardHeader(true)))

	return func(h http.Handler) http.Handler {
		// A HTTP handler is a function.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			middleware.Handler(h).ServeHTTP(w, r)
		})
	}
}
