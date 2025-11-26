package interpreter

import (
	"context"
	"io"
	ghttp "net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	icontext "github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/value"
)

const testBackendResponseBody = "falco_test_response"

func (i *Interpreter) TestProcessInit(r *http.Request) error {
	var err error
	if err = i.ProcessInit(r); err != nil {
		return errors.WithStack(err)
	}

	// If backend is not defined in main VCL, set virual backend
	if i.ctx.Backend == nil {
		i.ctx.Backend = &value.Backend{
			Value: &ast.BackendDeclaration{
				Name: &ast.Ident{Value: "falco_local_backend"},
				Properties: []*ast.BackendProperty{
					{
						Key:   &ast.Ident{Value: "host"},
						Value: &ast.String{Value: "localhost"},
					},
					{
						Key:   &ast.Ident{Value: "port"},
						Value: &ast.String{Value: "80"},
					},
				},
			},
		}
	}

	// On testing process, all request/response variables should be set initially
	i.ctx.BackendRequest, err = i.createBackendRequest(i.ctx, i.ctx.Backend)
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
			Body:          io.NopCloser(strings.NewReader(testBackendResponseBody)),
			ContentLength: int64(len(testBackendResponseBody)),
			Close:         true,
			Uncompressed:  false,
			Trailer:       ghttp.Header{},
			Request:       i.ctx.BackendRequest.Clone(context.Background()).Request,
		},
	}
	i.ctx.Response = i.ctx.BackendResponse.Clone()
	i.ctx.Object = i.ctx.BackendResponse.Clone()
	return nil
}

func (i *Interpreter) ProcessTestSubroutine(scope icontext.Scope, sub *ast.SubroutineDeclaration) error {
	i.SetScope(scope)
	if _, err := i.ProcessSubroutine(sub, DebugPass, nil); err != nil {
		return errors.WithStack(err)
	}
	return nil
}
