package interpreter

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

const testBackendResponseBody = "falco_test_response"

func (i *Interpreter) TestProcessInit(r *http.Request) error {
	var err error
	if err = i.ProcessInit(r); err != nil {
		return errors.WithStack(err)
	}

	// On testing process, all request/response variables should be set initially
	i.ctx.BackendRequest, err = i.createBackendRequest(i.ctx.Backend)
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
