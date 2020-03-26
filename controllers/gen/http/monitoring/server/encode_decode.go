// Code generated by goa v3.0.6, DO NOT EDIT.
//
// monitoring HTTP server encoders and decoders
//
// Command:
// $ goa gen github.com/anshap1719/authentication/design

package server

import (
	"context"
	"net/http"

	goahttp "goa.design/goa/v3/http"
)

// EncodeStatusResponse returns an encoder for responses returned by the
// monitoring status endpoint.
func EncodeStatusResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, interface{}) error {
	return func(ctx context.Context, w http.ResponseWriter, v interface{}) error {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}
