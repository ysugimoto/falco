package function

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	flchttp "github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_inspect(t *testing.T) {

	ctx := context.New()
	ctx.Request, _ = flchttp.NewRequest(http.MethodGet, "http://localhost:3124", nil)
	ctx.BackendRequest, _ = ctx.Request.Clone()
	ctx.BackendResponse = &flchttp.Response{
		StatusCode:    http.StatusOK,
		Status:        http.StatusText(http.StatusOK),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        flchttp.Header{},
		Body:          io.NopCloser(strings.NewReader("OK")),
		ContentLength: 2,
		Uncompressed:  false,
		Trailer:       flchttp.Header{},
	}
	ctx.Response = &flchttp.Response{
		StatusCode:    http.StatusOK,
		Status:        http.StatusText(http.StatusOK),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        flchttp.Header{},
		Body:          io.NopCloser(strings.NewReader("OK")),
		ContentLength: 2,
		Uncompressed:  false,
		Trailer:       flchttp.Header{},
	}
	ctx.Object = &flchttp.Response{
		StatusCode:    http.StatusOK,
		Status:        http.StatusText(http.StatusOK),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        flchttp.Header{},
		Body:          io.NopCloser(strings.NewReader("OK")),
		ContentLength: 2,
		Uncompressed:  false,
		Trailer:       flchttp.Header{},
	}

	t.Run("Inspect variable", func(t *testing.T) {
		tests := []struct {
			name    string
			expect  value.Value
			isError bool
		}{
			{name: "obj.status", expect: &value.Integer{Value: 500}},
			{name: "req.http.Foo", expect: &value.LenientString{IsNotSet: true}},
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
				t.Errorf("%s return value unmatch, diff=%s", tt.name, diff)
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
