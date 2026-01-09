package function

import (
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestStringImplicitConversion(t *testing.T) {
	now := time.Date(2025, 5, 13, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		argument value.Value
		expect   value.Value
		isError  bool
	}{
		{
			name:     "Convert Integer",
			argument: &value.Integer{Value: 10},
			expect:   &value.Integer{Value: 2},
		},
		{
			name:     "Convert Integer literal raises an error",
			argument: &value.Integer{Value: 10, Literal: true},
			isError:  true,
		},
		{
			name:     "Convert Float",
			argument: &value.Float{Value: 10.0},
			expect:   &value.Integer{Value: 6}, // 10.000
		},
		{
			name:     "Convert Float literal raises an error",
			argument: &value.Float{Value: 10.0, Literal: true},
			isError:  true,
		},
		{
			name:     "String is used as it is",
			argument: &value.String{Value: "foo"},
			expect:   &value.Integer{Value: 3},
		},
		{
			name:     "String literal is used as it is",
			argument: &value.String{Value: "foo", Literal: true},
			expect:   &value.Integer{Value: 3},
		},
		{
			name:     "NotSet string is used as empty string",
			argument: &value.String{IsNotSet: true},
			expect:   &value.Integer{Value: 0},
		},
		{
			name:     "Convert Bool",
			argument: &value.Boolean{Value: true},
			expect:   &value.Integer{Value: 1}, // 1
		},
		{
			name:     "Convert Bool literal raises an error",
			argument: &value.Boolean{Value: true, Literal: true},
			isError:  true,
		},
		{
			name:     "Convert IP",
			argument: &value.IP{Value: net.ParseIP("192.168.0.1")},
			expect:   &value.Integer{Value: 11},
		},
		{
			name:     "Convert RTIME",
			argument: &value.RTime{Value: time.Second * 10},
			expect:   &value.Integer{Value: 6}, // 10.000
		},
		{
			name:     "Convert RTIME literal raises an error",
			argument: &value.RTime{Value: time.Second * 10, Literal: true},
			isError:  true,
		},
		{
			name:     "Convert TIME",
			argument: &value.Time{Value: now},
			expect:   &value.Integer{Value: 29},
		},
		{
			name: "Convert Backend raises an error",
			argument: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example_1"},
				},
			},
			expect: &value.Integer{Value: 9},
		},
		{
			name: "Convert Backend literal raises an error",
			argument: &value.Backend{
				Literal: true,
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: "example_1"},
				},
			},
			isError: true,
		},
		{
			name: "Convert ACL raises an error",
			argument: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{Value: "example_1"},
				},
			},
			isError: true,
		},
		{
			name: "Convert ACL literal raises an error",
			argument: &value.Acl{
				Literal: true,
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{Value: "example_1"},
				},
			},
			isError: true,
		},
	}

	strlen := builtinFunctions["std.strlen"]
	ctx := &context.Context{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, err := strlen.Call(ctx, tt.argument)
			if err != nil {
				if !tt.isError {
					t.Errorf("Unexpected error returned: %s", err)
				}
				return
			}
			if diff := cmp.Diff(tt.expect, ret); diff != "" {
				t.Errorf("Return value mismatch, diff=%s", diff)
			}
		})
	}
}
