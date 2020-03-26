// Code generated by goa v3.0.6, DO NOT EDIT.
//
// monitoring service
//
// Command:
// $ goa gen github.com/anshap1719/go-authentication/design

package monitoring

import (
	"context"

	goa "goa.design/goa/v3/pkg"
)

// Service is the monitoring service interface.
type Service interface {
	// Status implements status.
	Status(context.Context) (err error)
}

// ServiceName is the name of the service as defined in the design. This is the
// same value that is set in the endpoint request contexts under the ServiceKey
// key.
const ServiceName = "monitoring"

// MethodNames lists the service method names as defined in the design. These
// are the same values that are set in the endpoint request contexts under the
// MethodKey key.
var MethodNames = [1]string{"status"}

// MakeInternalServerError builds a goa.ServiceError from an error.
func MakeInternalServerError(err error) *goa.ServiceError {
	return &goa.ServiceError{
		Name:    "InternalServerError",
		ID:      goa.NewErrorID(),
		Message: err.Error(),
	}
}
