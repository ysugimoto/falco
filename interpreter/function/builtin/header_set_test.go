// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of header.set
// Arguments may be:
// - ID, STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/headers/header-set/
func Test_Header_set(t *testing.T) {

	t.Run("Invalid arguments", func(t *testing.T) {
		tests := []struct {
			name    value.Value
			expect  string
			isError bool
		}{
			{name: &value.String{Value: ""}, expect: ""},
			{name: &value.String{Value: "Invalid%Header$<>"}, expect: ""},
		}
		for i, tt := range tests {
			req := httptest.NewRequest(http.MethodGet, "http://localhost:3124", nil)
			ctx := &context.Context{Request: req}

			_, err := Header_set(ctx, &value.Ident{Value: "req"}, tt.name, &value.String{Value: "value"})
			if err != nil {
				t.Errorf("[%d] Unexpected error return: %s", i, err)
			}

			v, err := Header_get(ctx, &value.Ident{Value: "req"}, tt.name)
			if err != nil {
				t.Errorf("[%d] Unexpected error return: %s", i, err)
			}

			if diff := cmp.Diff(v, &value.String{Value: tt.expect}); diff != "" {
				t.Errorf("[%d] Unexpected value returned, diff=%s", i, diff)
			}
		}
	})

	t.Run("set for req", func(t *testing.T) {
		tests := []struct {
			name    value.Value
			expect  string
			isError bool
		}{
			{name: &value.String{Value: "X-Custom-Header"}, expect: "value"},
			{name: &value.String{Value: "X-Not-Found"}, expect: "value"},
			{name: &value.String{Value: "OBJECT:foo"}, expect: "value"},
			{name: &value.Integer{Value: 10}, expect: "value"},
			{name: &value.Integer{Value: 10, Literal: true}, isError: true},
			{name: &value.Float{Value: 10}, expect: "value"},
			{name: &value.Float{Value: 10, Literal: true}, isError: true},
			{name: &value.Boolean{Value: false}, expect: "value"},
			{name: &value.Boolean{Value: true, Literal: true}, expect: "value"}, // BOOL could be provide as literal
			{name: &value.RTime{Value: time.Second}, expect: "value"},
			{name: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{name: &value.Time{Value: time.Now()}, expect: ""},
			{name: &value.IP{Value: net.ParseIP("192.168.0.1")}, expect: "value"},
			{name: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, expect: "value"},
			{name: &value.Backend{
				Literal: true,
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
			{name: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
		}

		for i, tt := range tests {
			req := httptest.NewRequest(http.MethodGet, "http://localhost:3124", nil)
			ctx := &context.Context{Request: req}

			_, err := Header_set(ctx, &value.Ident{Value: "req"}, tt.name, &value.String{Value: "value"})
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_set should return error but nil", i)
				}
				continue
			} else {
				if err != nil {
					t.Errorf("[%d] Header_set should not return error but non-nil: %s", i, err)
					continue
				}
			}

			v, err := Header_get(ctx, &value.Ident{Value: "req"}, tt.name)
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_set should return error but nil", i)
				}
				continue
			} else {
				if err != nil {
					t.Errorf("[%d] Header_set should not return error but non-nil: %s", i, err)
					continue
				}
			}

			if diff := cmp.Diff(v, &value.String{Value: tt.expect}); diff != "" {
				t.Errorf("[%d] Unexpected value returned, diff=%s", i, diff)
			}
		}
	})
	t.Run("set for bereq", func(t *testing.T) {
		tests := []struct {
			name    value.Value
			expect  string
			isError bool
		}{
			{name: &value.String{Value: "X-Custom-Header"}, expect: "value"},
			{name: &value.String{Value: "X-Not-Found"}, expect: "value"},
			{name: &value.String{Value: "OBJECT:foo"}, expect: "value"},
			{name: &value.Integer{Value: 10}, expect: "value"},
			{name: &value.Integer{Value: 10, Literal: true}, isError: true},
			{name: &value.Float{Value: 10}, expect: "value"},
			{name: &value.Float{Value: 10, Literal: true}, isError: true},
			{name: &value.Boolean{Value: false}, expect: "value"},
			{name: &value.Boolean{Value: true, Literal: true}, expect: "value"}, // BOOL could be provide as literal
			{name: &value.RTime{Value: time.Second}, expect: "value"},
			{name: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{name: &value.Time{Value: time.Now()}, expect: ""},
			{name: &value.IP{Value: net.ParseIP("192.168.0.1")}, expect: "value"},
			{name: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, expect: "value"},
			{name: &value.Backend{
				Literal: true,
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
			{name: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
		}

		for i, tt := range tests {
			req := httptest.NewRequest(http.MethodGet, "http://localhost:3124", nil)
			ctx := &context.Context{BackendRequest: req}

			_, err := Header_set(ctx, &value.Ident{Value: "bereq"}, tt.name, &value.String{Value: "value"})
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_set should return error but nil", i)
				}
				continue
			} else {
				if err != nil {
					t.Errorf("[%d] Header_set should not return error but non-nil: %s", i, err)
					continue
				}
			}

			v, err := Header_get(ctx, &value.Ident{Value: "bereq"}, tt.name)
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_set should return error but nil", i)
				}
				continue
			} else {
				if err != nil {
					t.Errorf("[%d] Header_set should not return error but non-nil: %s", i, err)
					continue
				}
			}

			if diff := cmp.Diff(v, &value.String{Value: tt.expect}); diff != "" {
				t.Errorf("[%d] Unexpected value returned, diff=%s", i, diff)
			}
		}
	})
	t.Run("set for beresp", func(t *testing.T) {
		tests := []struct {
			name    value.Value
			expect  string
			isError bool
		}{
			{name: &value.String{Value: "X-Custom-Header"}, expect: "value"},
			{name: &value.String{Value: "X-Not-Found"}, expect: "value"},
			{name: &value.String{Value: "OBJECT:foo"}, expect: "value"},
			{name: &value.Integer{Value: 10}, expect: "value"},
			{name: &value.Integer{Value: 10, Literal: true}, isError: true},
			{name: &value.Float{Value: 10}, expect: "value"},
			{name: &value.Float{Value: 10, Literal: true}, isError: true},
			{name: &value.Boolean{Value: false}, expect: "value"},
			{name: &value.Boolean{Value: true, Literal: true}, expect: "value"}, // BOOL could be provide as literal
			{name: &value.RTime{Value: time.Second}, expect: "value"},
			{name: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{name: &value.Time{Value: time.Now()}, expect: ""},
			{name: &value.IP{Value: net.ParseIP("192.168.0.1")}, expect: "value"},
			{name: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, expect: "value"},
			{name: &value.Backend{
				Literal: true,
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
			{name: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
		}

		for i, tt := range tests {
			resp := &http.Response{Header: http.Header{}}
			ctx := &context.Context{BackendResponse: resp}

			_, err := Header_set(ctx, &value.Ident{Value: "beresp"}, tt.name, &value.String{Value: "value"})
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_set should return error but nil", i)
				}
				continue
			} else {
				if err != nil {
					t.Errorf("[%d] Header_set should not return error but non-nil: %s", i, err)
					continue
				}
			}

			v, err := Header_get(ctx, &value.Ident{Value: "beresp"}, tt.name)
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_set should return error but nil", i)
				}
				continue
			} else {
				if err != nil {
					t.Errorf("[%d] Header_set should not return error but non-nil: %s", i, err)
					continue
				}
			}

			if diff := cmp.Diff(v, &value.String{Value: tt.expect}); diff != "" {
				t.Errorf("[%d] Unexpected value returned, diff=%s", i, diff)
			}
		}
	})
	t.Run("set for obj", func(t *testing.T) {
		tests := []struct {
			name    value.Value
			expect  string
			isError bool
		}{
			{name: &value.String{Value: "X-Custom-Header"}, expect: "value"},
			{name: &value.String{Value: "X-Not-Found"}, expect: "value"},
			{name: &value.String{Value: "OBJECT:foo"}, expect: "value"},
			{name: &value.Integer{Value: 10}, expect: "value"},
			{name: &value.Integer{Value: 10, Literal: true}, isError: true},
			{name: &value.Float{Value: 10}, expect: "value"},
			{name: &value.Float{Value: 10, Literal: true}, isError: true},
			{name: &value.Boolean{Value: false}, expect: "value"},
			{name: &value.Boolean{Value: true, Literal: true}, expect: "value"}, // BOOL could be provide as literal
			{name: &value.RTime{Value: time.Second}, expect: "value"},
			{name: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{name: &value.Time{Value: time.Now()}, expect: ""},
			{name: &value.IP{Value: net.ParseIP("192.168.0.1")}, expect: "value"},
			{name: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, expect: "value"},
			{name: &value.Backend{
				Literal: true,
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
			{name: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
		}

		for i, tt := range tests {
			resp := &http.Response{Header: http.Header{}}
			ctx := &context.Context{Object: resp}

			_, err := Header_set(ctx, &value.Ident{Value: "obj"}, tt.name, &value.String{Value: "value"})
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_set should return error but nil", i)
				}
				continue
			} else {
				if err != nil {
					t.Errorf("[%d] Header_set should not return error but non-nil: %s", i, err)
					continue
				}
			}

			v, err := Header_get(ctx, &value.Ident{Value: "obj"}, tt.name)
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_set should return error but nil", i)
				}
				continue
			} else {
				if err != nil {
					t.Errorf("[%d] Header_set should not return error but non-nil: %s", i, err)
					continue
				}
			}

			if diff := cmp.Diff(v, &value.String{Value: tt.expect}); diff != "" {
				t.Errorf("[%d] Unexpected value returned, diff=%s", i, diff)
			}
		}
	})
	t.Run("set for response", func(t *testing.T) {
		tests := []struct {
			name    value.Value
			expect  string
			isError bool
		}{
			{name: &value.String{Value: "X-Custom-Header"}, expect: "value"},
			{name: &value.String{Value: "X-Not-Found"}, expect: "value"},
			{name: &value.String{Value: "OBJECT:foo"}, expect: "value"},
			{name: &value.Integer{Value: 10}, expect: "value"},
			{name: &value.Integer{Value: 10, Literal: true}, isError: true},
			{name: &value.Float{Value: 10}, expect: "value"},
			{name: &value.Float{Value: 10, Literal: true}, isError: true},
			{name: &value.Boolean{Value: false}, expect: "value"},
			{name: &value.Boolean{Value: true, Literal: true}, expect: "value"}, // BOOL could be provide as literal
			{name: &value.RTime{Value: time.Second}, expect: "value"},
			{name: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{name: &value.Time{Value: time.Now()}, expect: ""},
			{name: &value.IP{Value: net.ParseIP("192.168.0.1")}, expect: "value"},
			{name: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, expect: "value"},
			{name: &value.Backend{
				Literal: true,
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
			{name: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
		}

		for i, tt := range tests {
			resp := &http.Response{Header: http.Header{}}
			ctx := &context.Context{Response: resp}

			_, err := Header_set(ctx, &value.Ident{Value: "resp"}, tt.name, &value.String{Value: "value"})
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_set should return error but nil", i)
				}
				continue
			} else {
				if err != nil {
					t.Errorf("[%d] Header_set should not return error but non-nil: %s", i, err)
					continue
				}
			}

			v, err := Header_get(ctx, &value.Ident{Value: "resp"}, tt.name)
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_set should return error but nil", i)
				}
				continue
			} else {
				if err != nil {
					t.Errorf("[%d] Header_set should not return error but non-nil: %s", i, err)
					continue
				}
			}

			if diff := cmp.Diff(v, &value.String{Value: tt.expect}); diff != "" {
				t.Errorf("[%d] Unexpected value returned, diff=%s", i, diff)
			}
		}
	})
}
