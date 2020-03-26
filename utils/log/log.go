package authlogs

import (
	"context"
	"goa.design/goa/v3/middleware"
	goa "goa.design/goa/v3/pkg"
	"log"
)

func ErrorLogger(l *log.Logger, prefix string) func(goa.Endpoint) goa.Endpoint {
	return func(e goa.Endpoint) goa.Endpoint {
		// A Goa endpoint is itself a function.
		return goa.Endpoint(func(ctx context.Context, req interface{}) (interface{}, error) {
			// Call the original endpoint function.
			res, err := e(ctx, req)

			if err != nil {
				reqID := ctx.Value(middleware.RequestIDKey).(string)

				l.Printf("[%s]: [%s] ERROR: %s", prefix, reqID, err.Error())
			}

			return res, err
		})
	}
}
