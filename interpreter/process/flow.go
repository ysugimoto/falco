package process

import (
	"context"

	"github.com/ysugimoto/falco/ast"
	icontext "github.com/ysugimoto/falco/interpreter/context"
)

type Flow struct {
	File            string    `json:"file"`
	Line            int       `json:"line"`
	Position        int       `json:"position"`
	Subroutine      string    `json:"subroutine"`
	Request         *HttpFlow `json:"req,omitempty"`
	BackendRequest  *HttpFlow `json:"bereq,omitempty"`
	BackendResponse *HttpFlow `json:"beresp,omitempty"`
	Response        *HttpFlow `json:"resp,omitempty"`
	Object          *HttpFlow `json:"object,omitempty"`
}

func NewFlow(ctx *icontext.Context, sub *ast.SubroutineDeclaration) *Flow {
	c := context.Background()

	token := sub.GetMeta().Token
	f := &Flow{
		File:       token.File,
		Line:       token.Line,
		Position:   token.Position,
		Subroutine: sub.Name.Value,
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
