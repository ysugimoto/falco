package process

import (
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
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

func NewFlow(ctx *context.Context, sub *ast.SubroutineDeclaration) *Flow {
	token := sub.GetMeta().Token
	f := &Flow{
		File:       token.File,
		Line:       token.Line,
		Position:   token.Position,
		Subroutine: sub.Name.Value,
	}
	if ctx.Request != nil {
		cloned, _ := ctx.Request.Clone()
		f.Request = newFlowRequest(cloned)
	}
	if ctx.BackendRequest != nil {
		cloned, _ := ctx.BackendRequest.Clone()
		f.BackendRequest = newFlowRequest(cloned)
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
