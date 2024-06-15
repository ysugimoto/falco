package process

import (
	"context"

	icontext "github.com/ysugimoto/falco/interpreter/context"
)

type Flow struct {
	File            string    `json:"file"`
	Line            int       `json:"line"`
	Position        int       `json:"position"`
	Subroutine      string    `json:"subroutine,omitempty"`
	Name            string    `json:"name,omitempty"`
	Scope           string    `json:"scope"`
	Request         *HttpFlow `json:"req,omitempty"`
	BackendRequest  *HttpFlow `json:"bereq,omitempty"`
	BackendResponse *HttpFlow `json:"beresp,omitempty"`
	Response        *HttpFlow `json:"resp,omitempty"`
	Object          *HttpFlow `json:"object,omitempty"`
}

func NewFlow(ctx *icontext.Context, opts ...Option) *Flow {
	c := context.Background()

	f := &Flow{
		Scope: ctx.Scope.String(),
	}
	for i := range opts {
		opts[i](f)
	}
	if ctx.Request != nil {
		f.Request = newFlowRequest(ctx.Request.Clone(c))
	}
	if ctx.BackendRequest != nil {
		f.BackendRequest = newFlowRequest(ctx.BackendRequest.Clone(c))
	}
	if ctx.BackendResponse != nil {
		f.BackendResponse = newFlowResponse(ctx.BackendResponse)
	}
	if ctx.Response != nil {
		f.Response = newFlowResponse(ctx.Response)
	}
	if ctx.Object != nil {
		f.Object = newFlowResponse(ctx.Object)
	}
	return f
}
