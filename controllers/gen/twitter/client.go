// Code generated by goa v3.0.6, DO NOT EDIT.
//
// twitter client
//
// Command:
// $ goa gen github.com/anshap1719/go-authentication/design

package twitter

import (
	"context"

	goa "goa.design/goa/v3/pkg"
)

// Client is the "twitter" service client.
type Client struct {
	RegisterURLEndpoint       goa.Endpoint
	AttachToAccountEndpoint   goa.Endpoint
	DetachFromAccountEndpoint goa.Endpoint
	ReceiveEndpoint           goa.Endpoint
}

// NewClient initializes a "twitter" service client given the endpoints.
func NewClient(registerURL, attachToAccount, detachFromAccount, receive goa.Endpoint) *Client {
	return &Client{
		RegisterURLEndpoint:       registerURL,
		AttachToAccountEndpoint:   attachToAccount,
		DetachFromAccountEndpoint: detachFromAccount,
		ReceiveEndpoint:           receive,
	}
}

// RegisterURL calls the "register-url" endpoint of the "twitter" service.
// RegisterURL may return the following errors:
//	- "InternalServerError" (type *goa.ServiceError)
//	- error: internal error
func (c *Client) RegisterURL(ctx context.Context, p *RegisterURLPayload) (res string, err error) {
	var ires interface{}
	ires, err = c.RegisterURLEndpoint(ctx, p)
	if err != nil {
		return
	}
	return ires.(string), nil
}

// AttachToAccount calls the "attach-to-account" endpoint of the "twitter"
// service.
// AttachToAccount may return the following errors:
//	- "InternalServerError" (type *goa.ServiceError)
//	- error: internal error
func (c *Client) AttachToAccount(ctx context.Context, p *AttachToAccountPayload) (res string, err error) {
	var ires interface{}
	ires, err = c.AttachToAccountEndpoint(ctx, p)
	if err != nil {
		return
	}
	return ires.(string), nil
}

// DetachFromAccount calls the "detach-from-account" endpoint of the "twitter"
// service.
// DetachFromAccount may return the following errors:
//	- "NotFound" (type *goa.ServiceError)
//	- "Forbidden" (type *goa.ServiceError)
//	- "InternalServerError" (type *goa.ServiceError)
//	- error: internal error
func (c *Client) DetachFromAccount(ctx context.Context, p *DetachFromAccountPayload) (err error) {
	_, err = c.DetachFromAccountEndpoint(ctx, p)
	return
}

// Receive calls the "receive" endpoint of the "twitter" service.
// Receive may return the following errors:
//	- "Unauthorized" (type *goa.ServiceError)
//	- "BadRequest" (type *goa.ServiceError)
//	- "InternalServerError" (type *goa.ServiceError)
//	- error: internal error
func (c *Client) Receive(ctx context.Context, p *ReceivePayload) (res *UserMedia, err error) {
	var ires interface{}
	ires, err = c.ReceiveEndpoint(ctx, p)
	if err != nil {
		return
	}
	return ires.(*UserMedia), nil
}
