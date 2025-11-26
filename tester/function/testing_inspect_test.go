package function

import (
	"io"
	ghttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_inspect(t *testing.T) {

	ctx := context.New()
	ctx.Request = http.WrapRequest(
		httptest.NewRequest(ghttp.MethodGet, "http://localhost:3124", nil),
	)
	ctx.BackendRequest = ctx.Request.Clone(ctx.Request.Context())
	ctx.BackendResponse = http.WrapResponse(
		&ghttp.Response{
			StatusCode:    ghttp.StatusOK,
			Status:        ghttp.StatusText(ghttp.StatusOK),
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        ghttp.Header{},
			Body:          io.NopCloser(strings.NewReader("OK")),
			ContentLength: 2,
			Close:         true,
			Uncompressed:  false,
			Trailer:       ghttp.Header{},
			Request:       ctx.BackendRequest.Clone(ctx.Request.Context()).Request,
		},
	)
	ctx.Response = http.WrapResponse(
		&ghttp.Response{
			StatusCode:    ghttp.StatusOK,
			Status:        ghttp.StatusText(ghttp.StatusOK),
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        ghttp.Header{},
			Body:          io.NopCloser(strings.NewReader("OK")),
			ContentLength: 2,
			Close:         true,
			Uncompressed:  false,
			Trailer:       ghttp.Header{},
			Request:       ctx.BackendRequest.Clone(ctx.Request.Context()).Request,
		},
	)
	ctx.Object = http.WrapResponse(
		&ghttp.Response{
			StatusCode:    ghttp.StatusOK,
			Status:        ghttp.StatusText(ghttp.StatusOK),
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        ghttp.Header{},
			Body:          io.NopCloser(strings.NewReader("OK")),
			ContentLength: 2,
			Close:         true,
			Uncompressed:  false,
			Trailer:       ghttp.Header{},
			Request:       ctx.BackendRequest.Clone(ctx.Request.Context()).Request,
		},
	)

	t.Run("Inspect variable", func(t *testing.T) {
		tests := []struct {
			name    string
			expect  value.Value
			isError bool
		}{
			{name: "obj.status", expect: &value.Integer{Value: 500}},
			{name: "req.http.Foo", expect: &value.String{IsNotSet: true}},
			{name: "some.undefined", isError: true},
		}

		for _, tt := range tests {
			ret, err := Testing_inspect(ctx, &value.String{Value: tt.name})
			if tt.isError {
				if err == nil {
					t.Errorf("Expect error but nil")
				}
				continue
			}
			if err != nil {
				t.Errorf("Unexpected error on Testing_inspect, %s", err)
				return
			}
			if diff := cmp.Diff(ret, tt.expect); diff != "" {
				t.Errorf("return value unmatch, diff=%s", diff)
			}
		}
	})
	t.Run("Other type inspection", func(t *testing.T) {
		tests := []struct {
			name value.Value
		}{
			{name: &value.Float{Value: 0}},
			{name: &value.Boolean{Value: false}},
			{name: &value.IP{Value: nil}},
			{name: &value.Backend{Value: nil}},
			{name: &value.Acl{Value: nil}},
		}

		for _, tt := range tests {
			_, err := Testing_inspect(ctx, tt.name)
			if err == nil {
				t.Errorf("Expected error but nil")
			}
		}
	})
}
