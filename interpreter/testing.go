package interpreter

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/value"
)

const testBackendResponseBody = "falco_test_response"

func (i *Interpreter) TestProcessInit(r *http.Request) error {
	var err error
	if err = i.ProcessInit(r); err != nil {
		return errors.WithStack(err)
	}

	// If backend is not defined in main VCL, set default or virual backend
	if len(i.ctx.Backends) > 0 {
		// pick first backend
		for _, v := range i.ctx.Backends {
			i.ctx.Backend = v
			break
		}
	} else {
		// Set virtual backend
		i.ctx.Backend = &value.Backend{
			Value: &ast.BackendDeclaration{
				Name: &ast.Ident{Value: "falco_testing_backend"},
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
	i.ctx.BackendRequest, err = i.createBackendRequest(i.ctx, i.ctx.Backend)
	if err != nil {
		return errors.WithStack(err)
	}
	i.ctx.BackendResponse = &http.Response{
		StatusCode:    http.StatusOK,
		Status:        http.StatusText(http.StatusOK),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		Body:          io.NopCloser(strings.NewReader(testBackendResponseBody)),
		ContentLength: int64(len(testBackendResponseBody)),
		Close:         true,
		Uncompressed:  false,
		Trailer:       http.Header{},
		Request:       i.ctx.BackendRequest.Clone(context.Background()),
	}
	i.ctx.Response = i.cloneResponse(i.ctx.BackendResponse)
	i.ctx.Object = i.cloneResponse(i.ctx.BackendResponse)
	return nil
}
