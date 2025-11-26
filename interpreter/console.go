package interpreter

import (
	"io"
	ghttp "net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/process"
	"github.com/ysugimoto/falco/interpreter/variable"
)

const consoleBackendResponseBody = "falco_console_response"

func (i *Interpreter) ConsoleProcessInit() error {
	var err error
	i.ctx = context.New(i.options...)

	// On console process, all request/response variables should be set initially
	i.ctx.Request, err = http.NewRequest(ghttp.MethodGet, "http://localhost:3124", nil)
	if err != nil {
		return errors.WithStack(err)
	}
	i.ctx.BackendRequest, err = http.NewRequest(ghttp.MethodGet, "http://localhost:3124", nil)
	if err != nil {
		return errors.WithStack(err)
	}
	i.ctx.BackendResponse = &http.Response{
		Response: &ghttp.Response{
			StatusCode:    ghttp.StatusOK,
			Status:        ghttp.StatusText(ghttp.StatusOK),
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        ghttp.Header{},
			Body:          io.NopCloser(strings.NewReader(consoleBackendResponseBody)),
			ContentLength: int64(len(consoleBackendResponseBody)),
			Close:         true,
			Uncompressed:  false,
			Trailer:       ghttp.Header{},
			Request:       nil,
		},
	}
	i.ctx.Response = i.ctx.BackendResponse.Clone()
	i.ctx.Object = i.ctx.BackendResponse.Clone()
	i.ctx.Scope = context.InitScope
	i.process = process.New()
	i.vars = variable.NewAllScopeVariables(i.ctx)
	return nil
}
