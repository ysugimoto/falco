// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
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
			req := httptest.NewRequest(http.MethodGet, "http://localhost:3124", nil)
			req.Header.Set("X-Custom-Header", "value")
			req.Header.Add("Object", "foo=valuefoo")
			req.Header.Add("Object", "bar=valuebar")
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
			{name: &value.Integer{Value: 10}},
			{name: &value.Integer{Value: 10, Literal: true}, isError: true},
			{name: &value.Float{Value: 10}},
			{name: &value.Float{Value: 10, Literal: true}, isError: true},
			{name: &value.Boolean{Value: false}},
			{name: &value.Boolean{Value: true, Literal: true}}, // BOOL could be provide as literal
			{name: &value.RTime{Value: time.Second}},
			{name: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{name: &value.Time{Value: time.Now()}, isError: true},
			{name: &value.IP{Value: net.ParseIP("192.168.0.1")}},
			{name: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}},
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
			req.Header.Set("X-Custom-Header", "value")
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
				if actual != "" {
					t.Errorf("[%d] Could not be filtered header", i)
				}
			} else {
				if actual == "" {
					t.Errorf("[%d] Unexpected header has been filtered", i)
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
			{name: &value.Integer{Value: 10}},
			{name: &value.Integer{Value: 10, Literal: true}, isError: true},
			{name: &value.Float{Value: 10}},
			{name: &value.Float{Value: 10, Literal: true}, isError: true},
			{name: &value.Boolean{Value: false}},
			{name: &value.Boolean{Value: true, Literal: true}}, // BOOL could be provide as literal
			{name: &value.RTime{Value: time.Second}},
			{name: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{name: &value.Time{Value: time.Now()}, isError: true},
			{name: &value.IP{Value: net.ParseIP("192.168.0.1")}},
			{name: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}},
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
			req.Header.Set("X-Custom-Header", "value")
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
				if actual != "" {
					t.Errorf("[%d] Could not be filtered header", i)
				}
			} else {
				if actual == "" {
					t.Errorf("[%d] Unexpected header has been filtered", i)
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
			{name: &value.Integer{Value: 10}},
			{name: &value.Integer{Value: 10, Literal: true}, isError: true},
			{name: &value.Float{Value: 10}},
			{name: &value.Float{Value: 10, Literal: true}, isError: true},
			{name: &value.Boolean{Value: false}},
			{name: &value.Boolean{Value: true, Literal: true}}, // BOOL could be provide as literal
			{name: &value.RTime{Value: time.Second}},
			{name: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{name: &value.Time{Value: time.Now()}, isError: true},
			{name: &value.IP{Value: net.ParseIP("192.168.0.1")}},
			{name: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}},
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
			resp := &http.Response{
				Header: http.Header{},
			}
			resp.Header.Set("X-Custom-Header", "value")
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
				if actual != "" {
					t.Errorf("[%d] Could not be filtered header", i)
				}
			} else {
				if actual == "" {
					t.Errorf("[%d] Unexpected header has been filtered", i)
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
			{name: &value.Integer{Value: 10}},
			{name: &value.Integer{Value: 10, Literal: true}, isError: true},
			{name: &value.Float{Value: 10}},
			{name: &value.Float{Value: 10, Literal: true}, isError: true},
			{name: &value.Boolean{Value: false}},
			{name: &value.Boolean{Value: true, Literal: true}}, // BOOL could be provide as literal
			{name: &value.RTime{Value: time.Second}},
			{name: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{name: &value.Time{Value: time.Now()}, isError: true},
			{name: &value.IP{Value: net.ParseIP("192.168.0.1")}},
			{name: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}},
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
			resp := &http.Response{
				Header: http.Header{},
			}
			resp.Header.Set("X-Custom-Header", "value")
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
				if actual != "" {
					t.Errorf("[%d] Could not be filtered header", i)
				}
			} else {
				if actual == "" {
					t.Errorf("[%d] Unexpected header has been filtered", i)
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
			{name: &value.Integer{Value: 10}},
			{name: &value.Integer{Value: 10, Literal: true}, isError: true},
			{name: &value.Float{Value: 10}},
			{name: &value.Float{Value: 10, Literal: true}, isError: true},
			{name: &value.Boolean{Value: false}},
			{name: &value.Boolean{Value: true, Literal: true}}, // BOOL could be provide as literal
			{name: &value.RTime{Value: time.Second}},
			{name: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{name: &value.Time{Value: time.Now()}, isError: true},
			{name: &value.IP{Value: net.ParseIP("192.168.0.1")}},
			{name: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example"},
				},
			}},
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
			resp := &http.Response{
				Header: http.Header{},
			}
			resp.Header.Set("X-Custom-Header", "value")
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
				if actual != "" {
					t.Errorf("[%d] Could not be filtered header", i)
				}
			} else {
				if actual == "" {
					t.Errorf("[%d] Unexpected header has been filtered", i)
				}
			}
		}
	})

	t.Run("filter for object-like header", func(t *testing.T) {
		tests := []struct {
			name       value.Value
			isFiltered bool
			isError    bool
		}{
			{name: &value.String{Value: "Object:foo"}, isFiltered: true},
			{name: &value.String{Value: "Object:bar"}, isFiltered: false},
			{name: &value.String{Value: "Object:baz"}, isFiltered: false},
		}
		for i, tt := range tests {
			req := httptest.NewRequest(http.MethodGet, "http://localhost:3124", nil)
			req.Header.Set("X-Custom-Header", "value")
			req.Header.Add("Object", "foo=valuefoo")
			req.Header.Add("Object", "bar=valuebar")
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

			var exists bool
			for _, v := range req.Header.Values("Object") {
				spl := strings.SplitN(v, "=", 2)
				if spl[0] == "foo" {
					exists = true
					break
				}
			}

			if tt.isFiltered {
				if exists {
					t.Errorf("[%d] Could not be filtered header", i)
				}
			} else {
				if !exists {
					t.Errorf("[%d] Unexpected header has been filtered", i)
				}
			}
		}
	})
}
