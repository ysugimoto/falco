// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	flchttp "github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of header.unset
// Arguments may be:
// - ID, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/headers/header-unset/
func Test_Header_unset(t *testing.T) {
	t.Run("Invalid arguments", func(t *testing.T) {
		tests := []struct {
			name value.Value
		}{
			{name: &value.String{Value: ""}},
			{name: &value.String{Value: "Invalid%Header$<>"}},
		}
		for i, tt := range tests {
			req, _ := flchttp.NewRequest(http.MethodGet, "http://localhost:3124", nil)
			ctx := &context.Context{Request: req}
			ident := &value.Ident{Value: "req"}

			_, _ = Header_set(ctx, ident, tt.name, &value.String{Value: "value"})
			_, err := Header_unset(ctx, ident, tt.name)
			if err != nil {
				t.Errorf("[%d] Header_unset should not return error but non-nil: %s", i, err)
				continue
			}

			v, err := Header_get(ctx, ident, tt.name)
			if err != nil {
				t.Errorf("[%d] Header_unset should not return error but non-nil: %s", i, err)
				continue
			}
			if diff := cmp.Diff(v, &value.LenientString{IsNotSet: true}); diff != "" {
				t.Errorf("[%d] Unexpected value returned, diff=%s", i, diff)
			}
		}
	})

	t.Run("unset for req", func(t *testing.T) {
		tests := []struct {
			name    value.Value
			isError bool
		}{
			{name: &value.String{Value: "X-Custom-Header"}},
			{name: &value.String{Value: "X-Not-Found"}},
			{name: &value.String{Value: "OBJECT:foo"}},
			{name: &value.Integer{Value: 10}, isError: true},
			{name: &value.Integer{Value: 10, Literal: true}, isError: true},
			{name: &value.Float{Value: 10}, isError: true},
			{name: &value.Float{Value: 10, Literal: true}, isError: true},
			{name: &value.Boolean{Value: false}, isError: true},
			{name: &value.Boolean{Value: true, Literal: true}, isError: true},
			{name: &value.RTime{Value: time.Second}, isError: true},
			{name: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{name: &value.Time{Value: time.Now()}, isError: true},
			{name: &value.IP{Value: net.ParseIP("192.168.0.1")}, isError: true},
			{name: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
			{name: &value.Backend{
				Literal: true,
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
			{name: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{Value: "example"}}}, isError: true},
		}

		for i, tt := range tests {
			req, _ := flchttp.NewRequest(http.MethodGet, "http://localhost:3124", nil)
			ctx := &context.Context{Request: req}
			ident := &value.Ident{Value: "req"}

			_, _ = Header_set(ctx, ident, tt.name, &value.String{Value: "value"})
			_, err := Header_unset(ctx, ident, tt.name)
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_unset should return error but nil", i)
				}
				continue
			}
			if err != nil {
				t.Errorf("[%d] Header_unset should not return error but non-nil: %s", i, err)
				continue
			}

			v, err := Header_get(ctx, ident, tt.name)
			if err != nil {
				t.Errorf("[%d] Header_unset should not return error but non-nil: %s", i, err)
				continue
			}
			str := value.GetString(v).String()
			if str != "" {
				t.Errorf("[%d] Unexpected value returned, diff=%s", i, str)
			}
		}
	})
	t.Run("unset for bereq", func(t *testing.T) {
		tests := []struct {
			name    value.Value
			isError bool
		}{
			{name: &value.String{Value: "X-Custom-Header"}},
			{name: &value.String{Value: "X-Not-Found"}},
			{name: &value.String{Value: "OBJECT:foo"}},
			{name: &value.Integer{Value: 10}, isError: true},
			{name: &value.Integer{Value: 10, Literal: true}, isError: true},
			{name: &value.Float{Value: 10}, isError: true},
			{name: &value.Float{Value: 10, Literal: true}, isError: true},
			{name: &value.Boolean{Value: false}, isError: true},
			{name: &value.Boolean{Value: true, Literal: true}, isError: true},
			{name: &value.RTime{Value: time.Second}, isError: true},
			{name: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{name: &value.Time{Value: time.Now()}, isError: true},
			{name: &value.IP{Value: net.ParseIP("192.168.0.1")}, isError: true},
			{name: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
			{name: &value.Backend{
				Literal: true,
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
			{name: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{Value: "example"}}}, isError: true},
		}

		for i, tt := range tests {
			req, _ := flchttp.NewRequest(http.MethodGet, "http://localhost:3124", nil)
			ctx := &context.Context{BackendRequest: req}
			ident := &value.Ident{Value: "bereq"}

			_, _ = Header_set(ctx, ident, tt.name, &value.String{Value: "value"})
			_, err := Header_unset(ctx, ident, tt.name)
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_unset should return error but nil", i)
				}
				continue
			}
			if err != nil {
				t.Errorf("[%d] Header_unset should not return error but non-nil: %s", i, err)
				continue
			}

			v, err := Header_get(ctx, ident, tt.name)
			if err != nil {
				t.Errorf("[%d] Header_unset should not return error but non-nil: %s", i, err)
				continue
			}
			str := value.GetString(v).String()
			if str != "" {
				t.Errorf("[%d] Unexpected value returned, diff=%s", i, str)
			}
		}
	})
	t.Run("unset for beresp", func(t *testing.T) {
		tests := []struct {
			name    value.Value
			isError bool
		}{
			{name: &value.String{Value: "X-Custom-Header"}},
			{name: &value.String{Value: "X-Not-Found"}},
			{name: &value.String{Value: "OBJECT:foo"}},
			{name: &value.Integer{Value: 10}, isError: true},
			{name: &value.Integer{Value: 10, Literal: true}, isError: true},
			{name: &value.Float{Value: 10}, isError: true},
			{name: &value.Float{Value: 10, Literal: true}, isError: true},
			{name: &value.Boolean{Value: false}, isError: true},
			{name: &value.Boolean{Value: true, Literal: true}, isError: true},
			{name: &value.RTime{Value: time.Second}, isError: true},
			{name: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{name: &value.Time{Value: time.Now()}, isError: true},
			{name: &value.IP{Value: net.ParseIP("192.168.0.1")}, isError: true},
			{name: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
			{name: &value.Backend{
				Literal: true,
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
			{name: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{Value: "example"}}}, isError: true},
		}

		for i, tt := range tests {
			resp := &flchttp.Response{Header: flchttp.Header{}}
			ctx := &context.Context{BackendResponse: resp}
			ident := &value.Ident{Value: "beresp"}

			_, _ = Header_set(ctx, ident, tt.name, &value.String{Value: "value"})
			_, err := Header_unset(ctx, ident, tt.name)
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_unset should return error but nil", i)
				}
				continue
			}
			if err != nil {
				t.Errorf("[%d] Header_unset should not return error but non-nil: %s", i, err)
				continue
			}

			v, err := Header_get(ctx, ident, tt.name)
			if err != nil {
				t.Errorf("[%d] Header_unset should not return error but non-nil: %s", i, err)
				continue
			}
			str := value.GetString(v).String()
			if str != "" {
				t.Errorf("[%d] Unexpected value returned, diff=%s", i, str)
			}
		}
	})
	t.Run("unset for obj", func(t *testing.T) {
		tests := []struct {
			name    value.Value
			isError bool
		}{
			{name: &value.String{Value: "X-Custom-Header"}},
			{name: &value.String{Value: "X-Not-Found"}},
			{name: &value.String{Value: "OBJECT:foo"}},
			{name: &value.Integer{Value: 10}, isError: true},
			{name: &value.Integer{Value: 10, Literal: true}, isError: true},
			{name: &value.Float{Value: 10}, isError: true},
			{name: &value.Float{Value: 10, Literal: true}, isError: true},
			{name: &value.Boolean{Value: false}, isError: true},
			{name: &value.Boolean{Value: true, Literal: true}, isError: true},
			{name: &value.RTime{Value: time.Second}, isError: true},
			{name: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{name: &value.Time{Value: time.Now()}, isError: true},
			{name: &value.IP{Value: net.ParseIP("192.168.0.1")}, isError: true},
			{name: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
			{name: &value.Backend{
				Literal: true,
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
			{name: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{Value: "example"}}}, isError: true},
		}

		for i, tt := range tests {
			resp := &flchttp.Response{Header: flchttp.Header{}}
			ctx := &context.Context{Object: resp}
			ident := &value.Ident{Value: "obj"}

			_, _ = Header_set(ctx, ident, tt.name, &value.String{Value: "value"})
			_, err := Header_unset(ctx, ident, tt.name)
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_unset should return error but nil", i)
				}
				continue
			}
			if err != nil {
				t.Errorf("[%d] Header_unset should not return error but non-nil: %s", i, err)
				continue
			}

			v, err := Header_get(ctx, ident, tt.name)
			if err != nil {
				t.Errorf("[%d] Header_unset should not return error but non-nil: %s", i, err)
				continue
			}
			str := value.GetString(v).String()
			if str != "" {
				t.Errorf("[%d] Unexpected value returned, diff=%s", i, str)
			}
		}
	})
	t.Run("unset for response", func(t *testing.T) {
		tests := []struct {
			name    value.Value
			isError bool
		}{
			{name: &value.String{Value: "X-Custom-Header"}},
			{name: &value.String{Value: "X-Not-Found"}},
			{name: &value.String{Value: "OBJECT:foo"}},
			{name: &value.Integer{Value: 10}, isError: true},
			{name: &value.Integer{Value: 10, Literal: true}, isError: true},
			{name: &value.Float{Value: 10}, isError: true},
			{name: &value.Float{Value: 10, Literal: true}, isError: true},
			{name: &value.Boolean{Value: false}, isError: true},
			{name: &value.Boolean{Value: true, Literal: true}, isError: true},
			{name: &value.RTime{Value: time.Second}, isError: true},
			{name: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{name: &value.Time{Value: time.Now()}, isError: true},
			{name: &value.IP{Value: net.ParseIP("192.168.0.1")}, isError: true},
			{name: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
			{name: &value.Backend{
				Literal: true,
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
			{name: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{Value: "example"}}}, isError: true},
		}

		for i, tt := range tests {
			resp := &flchttp.Response{Header: flchttp.Header{}}
			ctx := &context.Context{Response: resp}
			ident := &value.Ident{Value: "resp"}

			_, _ = Header_set(ctx, ident, tt.name, &value.String{Value: "value"})
			_, err := Header_unset(ctx, ident, tt.name)
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_unset should return error but nil", i)
				}
				continue
			}
			if err != nil {
				t.Errorf("[%d] Header_unset should not return error but non-nil: %s", i, err)
				continue
			}

			v, err := Header_get(ctx, ident, tt.name)
			if err != nil {
				t.Errorf("[%d] Header_unset should not return error but non-nil: %s", i, err)
				continue
			}
			str := value.GetString(v).String()
			if str != "" {
				t.Errorf("[%d] Unexpected value returned, diff=%s", i, str)
			}
		}
	})
}
