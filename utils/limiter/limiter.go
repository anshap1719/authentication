package limiter

import (
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/middleware/stdlib"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"log"
	"net/http"
)

var Store = memory.NewStore()

type serviceAccountDetails struct {
	AccountID     string `json:"accountId,omitempty" bson:"accountId,omitempty"`
	AccountSecret string `json:"accountSecret,omitempty" bson:"accountSecret,omitempty"`
}

func RateLimitSocialServices() func(http.Handler) http.Handler {
	rate, err := limiter.NewRateFromFormatted("20000-H")
	if err != nil {
		log.Fatal(err)
	}

	middleware := stdlib.NewMiddleware(limiter.New(Store, rate, limiter.WithTrustForwardHeader(true)))

	return func(h http.Handler) http.Handler {
		// A HTTP handler is a function.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if checkToken(r.Header) {
				h.ServeHTTP(w, r)
			} else {
				middleware.Handler(h).ServeHTTP(w, r)
			}
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
			if checkToken(r.Header) {
				h.ServeHTTP(w, r)
			} else {
				middleware.Handler(h).ServeHTTP(w, r)
			}
		})
	}
}

func checkToken(headers http.Header) bool {
	return false
	//token := headers.Get("Account-ID")
	//if token == "" {
	//	return false
	//}
	//var sad serviceAccountDetails
	//
	//if err := database.GetCollection("ServiceAccounts").Find(bson.M{"account_id": token}).One(&sad); err != nil {
	//	return false
	//}
	//
	//return sad.AccountSecret == headers.Get("Account-Secret")
}
