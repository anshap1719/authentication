package controllers

import (
	"context"
	"log"

	monitoring "github.com/anshap1719/authentication/controllers/gen/monitoring"
)

// monitoring service example implementation.
// The example methods log the requests and return zero values.
type monitoringsrvc struct {
	logger *log.Logger
}

// NewMonitoring returns the monitoring service implementation.
func NewMonitoring(logger *log.Logger) monitoring.Service {
	return &monitoringsrvc{logger}
}

// Status implements status.
func (s *monitoringsrvc) Status(ctx context.Context) (err error) {
	s.logger.Print("monitoring.status")
	return
}
