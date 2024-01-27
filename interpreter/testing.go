package interpreter

import (
	"io"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	flchttp "github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/transport"
	"github.com/ysugimoto/falco/interpreter/value"
)

const testBackendResponseBody = "falco_test_response"

func (i *Interpreter) ProcessTestSubroutine(scope context.Scope, sub *ast.SubroutineDeclaration) error {
	i.SetScope(scope)
	if _, err := i.ProcessSubroutine(sub, DebugPass); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

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
						Value: &ast.String{Value: "http://localhost:3124"},
					},
				},
			},
		}
	}

	// On testing process, all request/response variables should be set initially
	i.ctx.BackendRequest, err = transport.BackendRequest(i.ctx, i.ctx.Backend)
	if err != nil {
		return errors.WithStack(err)
	}
	i.ctx.BackendResponse = &flchttp.Response{
		StatusCode:    http.StatusOK,
		Status:        http.StatusText(http.StatusOK),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        flchttp.Header{},
		Body:          io.NopCloser(strings.NewReader(testBackendResponseBody)),
		ContentLength: int64(len(testBackendResponseBody)),
		Uncompressed:  false,
	}
	i.ctx.Response, _ = i.ctx.BackendResponse.Clone()
	i.ctx.Object, _ = i.ctx.BackendResponse.Clone()
	return nil
}
