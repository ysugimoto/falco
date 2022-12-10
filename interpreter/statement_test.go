package interpreter

import (
	"testing"

	_ "github.com/k0kubun/pp"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/simulator/variable"
	"github.com/ysugimoto/falco/simulator/types"
)

func TestDeclareStatement(t *testing.T) {
	tests := []struct{
		name string
		decl *ast.DeclareStatement
		expect variable.Value
		isError bool
	}{
		{
			name: "INTEGER variable declaration",
			decl: &ast.DeclareStatement{
				Name: &ast.Ident{ Value: "var.foo" },
				ValueType: &ast.Ident{ Value: "INTEGER" },
			},
			expect: &variable.Integer{},
		},
		{
			name: "FLOAT variable declaration",
			decl: &ast.DeclareStatement{
				Name: &ast.Ident{ Value: "var.foo" },
				ValueType: &ast.Ident{ Value: "FLOAT" },
			},
			expect: &variable.Float{},
		},
		{
			name: "BOOL variable declaration",
			decl: &ast.DeclareStatement{
				Name: &ast.Ident{ Value: "var.foo" },
				ValueType: &ast.Ident{ Value: "BOOL" },
			},
			expect: &variable.Boolean{},
		},
		{
			name: "BACKEND variable declaration",
			decl: &ast.DeclareStatement{
				Name: &ast.Ident{ Value: "var.foo" },
				ValueType: &ast.Ident{ Value: "BACKEND" },
			},
			expect: &variable.Backend{},
		},
		{
			name: "IP variable declaration",
			decl: &ast.DeclareStatement{
				Name: &ast.Ident{ Value: "var.foo" },
				ValueType: &ast.Ident{ Value: "IP" },
			},
			expect: &variable.IP{},
		},
		{
			name: "STRING variable declaration",
			decl: &ast.DeclareStatement{
				Name: &ast.Ident{ Value: "var.foo" },
				ValueType: &ast.Ident{ Value: "STRING" },
			},
			expect: &variable.String{},
		},
		{
			name: "RTIME variable declaration",
			decl: &ast.DeclareStatement{
				Name: &ast.Ident{ Value: "var.foo" },
				ValueType: &ast.Ident{ Value: "RTIME" },
			},
			expect: &variable.RTime{},
		},
		{
			name: "TIME variable declaration",
			decl: &ast.DeclareStatement{
				Name: &ast.Ident{ Value: "var.foo" },
				ValueType: &ast.Ident{ Value: "TIME" },
			},
			expect: &variable.Time{},
		},
		{
			name: "ACL variable declaration",
			decl: &ast.DeclareStatement{
				Name: &ast.Ident{ Value: "var.foo" },
				ValueType: &ast.Ident{ Value: "ACL" },
			},
			isError: true,
		},
	}

	for _, tt := range tests {
		ip := New(nil)
		err := ip.ProcessDeclareStatement(tt.decl)
		if err != nil {
			if !tt.isError {
				t.Errorf("%s: unexpected error returned: %s", tt.name, err)
			}
			continue
		}
		v := ip.vars.Get(tt.decl.Name.Value)
		if v == nil {
			t.Errorf("%s: %s varible must be declared", tt.name, tt.decl.Name.Value)
			continue
		}
		if v.Value.String() != tt.expect.String() {
			t.Errorf("%s: declared value mismatch, expect %s, got %s", tt.name, tt.expect, v.Value)
		}
	}
}

func TestReturnStatement(t *testing.T) {
	var exp ast.Expression = &ast.Ident{
		Value: "pass",
		Meta: &ast.Meta{},
	}
	tests := []struct {
		name string
		stmt *ast.ReturnStatement
		expect State
	}{
		{
			name: "should return pass state",
			stmt: &ast.ReturnStatement{
				ReturnExpression: &exp,
			},
			expect: PASS,
		},
	}

	for _, tt := range tests {
		ip := New(nil)
		s := ip.ProcessReturnStatement(tt.stmt)
		if s != tt.expect {
			t.Errorf("%s expects state %s, got %s", tt.name, tt.expect, s)
		}
	}
}

func TestSetStatement(t *testing.T) {

	t.Run("Set HTTP Header", func(t *testing.T) {
		ip := New(nil)
		ip.scope = types.RecvScope
		ip.vars = variable.PredefinedVariables()
		err := ip.ProcessSetStatement(&ast.SetStatement{
			Ident: &ast.Ident{
				Value: "req.http.Foo",
			},
			Value: &ast.String{ Value: "foo" },
		})
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
			return
		}
		v := ip.vars.Get("req.http.Foo")
		if v == nil {
			t.Errorf("Variable should be exists")
			return
		}
		s := variable.Unwrap[*variable.String](v.Value)
		if s.Value != "foo" {
			t.Errorf(`set value should be "foo"`)
		}
	})

	t.Run("Set local variable", func(t *testing.T) {
		ip := New(nil)
		ip.vars = variable.PredefinedVariables()
		if err := ip.ProcessDeclareStatement(&ast.DeclareStatement{
			Name: &ast.Ident{ Value: "var.foo" },
			ValueType: &ast.Ident{ Value: "STRING" },
		}); err != nil {
			t.Errorf("Unexpected error on declaration: %s", err)
			return
		}

		err := ip.ProcessSetStatement(&ast.SetStatement{
			Ident: &ast.Ident{
				Value: "var.foo",
			},
			Value: &ast.String{ Value: "foo" },
		})
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
			return
		}
		v := ip.vars.Get("var.foo")
		if v == nil {
			t.Errorf("Variable should be exists")
			return
		}
		s := variable.Unwrap[*variable.String](v.Value)
		if s.Value != "foo" {
			t.Errorf(`set value should be "foo"`)
		}
	})

	t.Run("Error on undefined variable", func(t *testing.T) {
		ip := New(nil)
		ip.vars = variable.PredefinedVariables()
		err := ip.ProcessSetStatement(&ast.SetStatement{
			Ident: &ast.Ident{
				Value: "var.foo",
			},
			Value: &ast.String{ Value: "foo" },
		})
		if err == nil {
			t.Errorf("err should be non-nil, but got nil")
			return
		}
	})
}
