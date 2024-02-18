// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	flchttp "github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of header.filter
// Arguments may be:
// - ID, STRING_LIST
// Reference: https://developer.fastly.com/reference/vcl/functions/headers/header-filter/
func Test_Header_filter(t *testing.T) {
	t.Run("Invalis argument", func(t *testing.T) {
		tests := []struct {
			name       value.Value
			isFiltered bool
			isError    bool
		}{
			{name: &value.String{Value: ""}, isError: true},
			{name: &value.String{Value: "Invalid%Header$<>"}, isError: true},
		}
		for i, tt := range tests {
			req, _ := flchttp.NewRequest(http.MethodGet, "http://localhost:3124", nil)
			req.Header.Set("X-Custom-Header", &value.String{Value: "value"})
			req.Header.Set("Object:foo", &value.String{Value: "valuefoo"})
			req.Header.Set("Object:bar", &value.String{Value: "valuebar"})
			ctx := &context.Context{Request: req}

			_, err := Header_filter(ctx, &value.Ident{Value: "req"}, tt.name)
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_filter should return error but nil", i)
				}
				continue
			} else {
				if err != nil {
					t.Errorf("[%d] Header_filter should not return error but non-nil: %s", i, err)
				}
			}
		}
	})

	t.Run("filter from req", func(t *testing.T) {
		tests := []struct {
			name       value.Value
			isFiltered bool
			isError    bool
		}{
			{name: &value.String{Value: "X-Custom-Header"}, isFiltered: true},
			{name: &value.String{Value: "X-Not-Found"}},
			{name: &value.String{Value: "Content-Length"}, isError: true},
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
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
		}

		for i, tt := range tests {
			req, _ := flchttp.NewRequest(http.MethodGet, "http://localhost:3124", nil)
			req.Header.Set("X-Custom-Header", &value.String{Value: "value"})
			ctx := &context.Context{Request: req}

			_, err := Header_filter(ctx, &value.Ident{Value: "req"}, tt.name)
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_filter should return error but nil", i)
				}
				continue
			} else {
				if err != nil {
					t.Errorf("[%d] Header_filter should not return error but non-nil: %s", i, err)
					continue
				}
			}

			actual := req.Header.Get("X-Custom-Header")
			if tt.isFiltered {
				if !actual.IsNotSet {
					t.Errorf("[%d] Could not filter expected header", i)
				}
			} else {
				if actual.IsNotSet {
					t.Errorf("[%d] Header Should not be filtered ", i)
				}
			}
		}
	})

	t.Run("filter from bereq", func(t *testing.T) {
		tests := []struct {
			name       value.Value
			isFiltered bool
			isError    bool
		}{
			{name: &value.String{Value: "X-Custom-Header"}, isFiltered: true},
			{name: &value.String{Value: "X-Not-Found"}},
			{name: &value.String{Value: "Content-Length"}, isError: true},
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
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
		}

		for i, tt := range tests {
			req, _ := flchttp.NewRequest(http.MethodGet, "http://localhost:3124", nil)
			req.Header.Set("X-Custom-Header", &value.String{Value: "value"})
			ctx := &context.Context{BackendRequest: req}

			_, err := Header_filter(ctx, &value.Ident{Value: "bereq"}, tt.name)
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_filter should return error but nil", i)
				}
				continue
			} else {
				if err != nil {
					t.Errorf("[%d] Header_filter should not return error but non-nil: %s", i, err)
					continue
				}
			}

			actual := req.Header.Get("X-Custom-Header")
			if tt.isFiltered {
				if !actual.IsNotSet {
					t.Errorf("[%d] Could not filter expected header", i)
				}
			} else {
				if actual.IsNotSet {
					t.Errorf("[%d] Header Should not be filtered ", i)
				}
			}
		}
	})

	t.Run("filter from beresp", func(t *testing.T) {
		tests := []struct {
			name       value.Value
			isFiltered bool
			isError    bool
		}{
			{name: &value.String{Value: "X-Custom-Header"}, isFiltered: true},
			{name: &value.String{Value: "X-Not-Found"}},
			{name: &value.String{Value: "Content-Length"}, isError: true},
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
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
		}

		for i, tt := range tests {
			resp := &flchttp.Response{
				Header: flchttp.Header{},
			}
			resp.Header.Set("X-Custom-Header", &value.String{Value: "value"})
			ctx := &context.Context{BackendResponse: resp}

			_, err := Header_filter(ctx, &value.Ident{Value: "beresp"}, tt.name)
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_filter should return error but nil", i)
				}
				continue
			} else {
				if err != nil {
					t.Errorf("[%d] Header_filter should not return error but non-nil: %s", i, err)
					continue
				}
			}

			actual := resp.Header.Get("X-Custom-Header")
			if tt.isFiltered {
				if !actual.IsNotSet {
					t.Errorf("[%d] Could not filter expected header", i)
				}
			} else {
				if actual.IsNotSet {
					t.Errorf("[%d] Header Should not be filtered ", i)
				}
			}
		}
	})

	t.Run("filter from obj", func(t *testing.T) {
		tests := []struct {
			name       value.Value
			isFiltered bool
			isError    bool
		}{
			{name: &value.String{Value: "X-Custom-Header"}, isFiltered: true},
			{name: &value.String{Value: "X-Not-Found"}},
			{name: &value.String{Value: "Content-Length"}, isError: true},
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
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
		}

		for i, tt := range tests {
			resp := &flchttp.Response{
				Header: flchttp.Header{},
			}
			resp.Header.Set("X-Custom-Header", &value.String{Value: "value"})
			ctx := &context.Context{Object: resp}

			_, err := Header_filter(ctx, &value.Ident{Value: "obj"}, tt.name)
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_filter should return error but nil", i)
				}
				continue
			} else {
				if err != nil {
					t.Errorf("[%d] Header_filter should not return error but non-nil: %s", i, err)
					continue
				}
			}

			actual := resp.Header.Get("X-Custom-Header")
			if tt.isFiltered {
				if !actual.IsNotSet {
					t.Errorf("[%d] Could not filter expected header", i)
				}
			} else {
				if actual.IsNotSet {
					t.Errorf("[%d] Header Should not be filtered ", i)
				}
			}
		}
	})

	t.Run("filter from response", func(t *testing.T) {
		tests := []struct {
			name       value.Value
			isFiltered bool
			isError    bool
		}{
			{name: &value.String{Value: "X-Custom-Header"}, isFiltered: true},
			{name: &value.String{Value: "X-Not-Found"}},
			{name: &value.String{Value: "Content-Length"}, isError: true},
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
					Name: &ast.Ident{Value: "example"},
				},
			}, isError: true},
		}

		for i, tt := range tests {
			resp := &flchttp.Response{
				Header: flchttp.Header{},
			}
			resp.Header.Set("X-Custom-Header", &value.String{Value: "value"})
			ctx := &context.Context{Response: resp}

			_, err := Header_filter(ctx, &value.Ident{Value: "resp"}, tt.name)
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_filter should return error but nil", i)
				}
				continue
			} else {
				if err != nil {
					t.Errorf("[%d] Header_filter should not return error but non-nil: %s", i, err)
					continue
				}
			}

			actual := resp.Header.Get("X-Custom-Header")
			if tt.isFiltered {
				if !actual.IsNotSet {
					t.Errorf("[%d] Could not filter expected header", i)
				}
			} else {
				if actual.IsNotSet {
					t.Errorf("[%d] Header Should not be filtered ", i)
				}
			}
		}
	})

	t.Run("filter for object-like header", func(t *testing.T) {
		tests := []struct {
			name       string
			isFiltered bool
			isError    bool
		}{
			{name: "Object:foo", isFiltered: true},
			{name: "Object:bar", isFiltered: true},
		}
		for i, tt := range tests {
			req, _ := flchttp.NewRequest(http.MethodGet, "http://localhost:3124", nil)
			req.Header.Set("X-Custom-Header", &value.String{Value: "value"})
			req.Header.Set("Object:foo", &value.String{Value: "valuefoo"})
			req.Header.Set("Object:bar", &value.String{Value: "valuebar"})
			ctx := &context.Context{Request: req}

			_, err := Header_filter(ctx, &value.Ident{Value: "req"}, &value.String{Value: tt.name})
			if tt.isError {
				if err == nil {
					t.Errorf("[%d] Header_filter should return error but nil", i)
				}
				continue
			} else {
				if err != nil {
					t.Errorf("[%d] Header_filter should not return error but non-nil: %s", i, err)
					continue
				}
			}

			actual := req.Header.Get(tt.name)
			if tt.isFiltered {
				if !actual.IsNotSet {
					t.Errorf("[%d] Could not filter expected header", i)
				}
			} else {
				if actual.IsNotSet {
					t.Errorf("[%d] Header Should not be filtered ", i)
				}
			}
		}
	})
}
