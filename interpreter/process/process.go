package process

import (
	"context"

	"net/http"

	"github.com/ysugimoto/falco/ast"
	icontext "github.com/ysugimoto/falco/interpreter/context"
)

type Log struct {
	Meta    *ast.Meta
	Message string
}

func NewLog(l *ast.LogStatement, message string) *Log {
	return &Log{
		Meta:    l.GetMeta(),
		Message: message,
	}

}

type Flow struct {
	Meta           *ast.Meta
	Name           string
	Request        *http.Request
	BackendRequest *http.Request
}

func NewFlow(ctx *icontext.Context, sub *ast.SubroutineDeclaration) *Flow {
	c := context.Background()

	f := &Flow{
		Meta: sub.GetMeta(),
		Name: sub.Name.Value,
	}
	if ctx.Request != nil {
		f.Request = ctx.Request.Clone(c)
	}
	if ctx.BackendRequest != nil {
		f.BackendRequest = ctx.BackendRequest.Clone(c)
	}
	return f
}

type Process struct {
	Flows    []*Flow
	Logs     []*Log
	Restarts int
	Errors   []error
}

func New() *Process {
	return &Process{
		Flows:  []*Flow{},
		Logs:   []*Log{},
		Errors: []error{},
	}
}
