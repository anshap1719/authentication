package ctx

import (
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"net/http"
	"strings"
)

type (
	CtxKey int
)

const (
	// RequestMethodKey is the request context key used to store r.Method created by
	// the PopulateRequestContext middleware.
	RequestMethodKey CtxKey = iota + 1

	// RequestURIKey is the request context key used to store r.RequestURI created by
	// the PopulateRequestContext middleware.
	RequestURIKey

	// RequestPathKey is the request context key used to store r.URL.Path created by
	// the PopulateRequestContext middleware.
	RequestPathKey

	// RequestProtoKey is the request context key used to store r.Proto created by
	// the PopulateRequestContext middleware.
	RequestProtoKey

	// RequestHostKey is the request context key used to store r.Host created by
	// the PopulateRequestContext middleware.
	RequestHostKey

	// RequestRemoteAddrKey is the request context key used to store r.RemoteAddr
	// created by the PopulateRequestContext middleware.
	RequestRemoteAddrKey

	// RequestXForwardedForKey is the request context key used to store the
	// X-Forwarded-For header created by the PopulateRequestContext middleware.
	RequestXForwardedForKey

	// RequestAuthorizationKey is the request context key used to store the
	// Authorization header created by the PopulateRequestContext middleware.
	RequestAuthorizationKey

	// RequestUserAgentKey is the request context key used to store the User-Agent
	// header created by the PopulateRequestContext middleware.
	RequestUserAgentKey
)

func PopulateRequestContext(database *mongo.Database) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			var proto string
			if strings.Contains(r.Host, "localhost") {
				proto = "http"
			} else {
				proto = "https"
			}

			for k, v := range map[CtxKey]string{
				RequestMethodKey:        r.Method,
				RequestURIKey:           r.RequestURI,
				RequestPathKey:          r.URL.Path,
				RequestProtoKey:         proto,
				RequestHostKey:          r.Host,
				RequestRemoteAddrKey:    r.RemoteAddr,
				RequestXForwardedForKey: r.Header.Get("X-Forwarded-For"),
				RequestAuthorizationKey: r.Header.Get("Authorization"),
				RequestUserAgentKey:     r.UserAgent(),
			} {
				ctx = context.WithValue(ctx, k, v)
			}

			h.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
