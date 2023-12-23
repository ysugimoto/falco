package interpreter

import (
	"net/http"
	"testing"
	"time"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestDeclareStatement(t *testing.T) {
	tests := []struct {
		name    string
		decl    *ast.DeclareStatement
		expect  value.Value
		isError bool
	}{
		{
			name: "INTEGER value declaration",
			decl: &ast.DeclareStatement{
				Name:      &ast.Ident{Value: "var.foo"},
				ValueType: &ast.Ident{Value: "INTEGER"},
			},
			expect: &value.Integer{},
		},
		{
			name: "FLOAT value declaration",
			decl: &ast.DeclareStatement{
				Name:      &ast.Ident{Value: "var.foo"},
				ValueType: &ast.Ident{Value: "FLOAT"},
			},
			expect: &value.Float{},
		},
		{
			name: "BOOL value declaration",
			decl: &ast.DeclareStatement{
				Name:      &ast.Ident{Value: "var.foo"},
				ValueType: &ast.Ident{Value: "BOOL"},
			},
			expect: &value.Boolean{},
		},
		{
			name: "BACKEND value declaration",
			decl: &ast.DeclareStatement{
				Name:      &ast.Ident{Value: "var.foo"},
				ValueType: &ast.Ident{Value: "BACKEND"},
			},
			expect: &value.Backend{},
		},
		{
			name: "IP value declaration",
			decl: &ast.DeclareStatement{
				Name:      &ast.Ident{Value: "var.foo"},
				ValueType: &ast.Ident{Value: "IP"},
			},
			expect: &value.IP{},
		},
		{
			name: "STRING value declaration",
			decl: &ast.DeclareStatement{
				Name:      &ast.Ident{Value: "var.foo"},
				ValueType: &ast.Ident{Value: "STRING"},
			},
			expect: &value.String{},
		},
		{
			name: "RTIME value declaration",
			decl: &ast.DeclareStatement{
				Name:      &ast.Ident{Value: "var.foo"},
				ValueType: &ast.Ident{Value: "RTIME"},
			},
			expect: &value.RTime{},
		},
		{
			name: "TIME value declaration",
			decl: &ast.DeclareStatement{
				Name:      &ast.Ident{Value: "var.foo"},
				ValueType: &ast.Ident{Value: "TIME"},
			},
			expect: &value.Time{
				Value: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			name: "ACL value declaration",
			decl: &ast.DeclareStatement{
				Name:      &ast.Ident{Value: "var.foo"},
				ValueType: &ast.Ident{Value: "ACL"},
			},
			isError: true,
		},
	}

	for _, tt := range tests {
		ip := New(nil)
		err := ip.localVars.Declare(tt.decl.Name.Value, tt.decl.ValueType.Value)
		if err != nil {
			if !tt.isError {
				t.Errorf("%s: unexpected error returned: %s", tt.name, err)
			}
			continue
		}

		v, err := ip.localVars.Get(tt.decl.Name.Value)
		if err != nil {
			t.Errorf("%s: %s varible must be declared: %s", tt.name, tt.decl.Name.Value, err)
			continue
		}
		assertValue(t, tt.name, tt.expect, v)
	}
}

func TestReturnStatement(t *testing.T) {
	var exp ast.Expression = &ast.Ident{
		Value: "pass",
		Meta:  &ast.Meta{},
	}
	tests := []struct {
		name   string
		stmt   *ast.ReturnStatement
		expect State
	}{
		{
			name: "should return pass state",
			stmt: &ast.ReturnStatement{
				ReturnExpression: &exp,
			},
			expect: PASS,
		},
		{
			name:   "should return none state",
			stmt:   &ast.ReturnStatement{},
			expect: BARE_RETURN,
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
	tests := []struct {
		name  string
		scope context.Scope
		stmt  *ast.SetStatement
	}{
		{
			name:  "set local variable",
			scope: context.RecvScope,
			stmt: &ast.SetStatement{
				Ident:    &ast.Ident{Value: "var.foo"},
				Operator: &ast.Operator{Operator: "="},
				Value:    &ast.Integer{Value: 100},
			},
		},
		{
			name:  "set client.geo.ip_override in vcl_recv",
			scope: context.RecvScope,
			stmt: &ast.SetStatement{
				Ident:    &ast.Ident{Value: "client.geo.ip_override"},
				Operator: &ast.Operator{Operator: "="},
				Value:    &ast.String{Value: "127.0.0.1"},
			},
		},
		{
			name:  "set bereq.http.Foo in vcl_miss",
			scope: context.MissScope,
			stmt: &ast.SetStatement{
				Ident:    &ast.Ident{Value: "bereq.http.Foo"},
				Operator: &ast.Operator{Operator: "="},
				Value:    &ast.String{Value: "test"},
			},
		},
		{
			name:  "set bereq.http.Foo in vcl_pass",
			scope: context.PassScope,
			stmt: &ast.SetStatement{
				Ident:    &ast.Ident{Value: "bereq.http.Foo"},
				Operator: &ast.Operator{Operator: "="},
				Value:    &ast.String{Value: "test"},
			},
		},
	}

	for _, tt := range tests {
		ip := New(nil)
		if err := ip.localVars.Declare("var.foo", "INTEGER"); err != nil {
			t.Errorf("%s: unexpected error returned: %s", tt.name, err)
		}

		ip.ctx = context.New()
		ip.SetScope(tt.scope)
		req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
		if err != nil {
			t.Errorf("%s: unexpected error returned: %s", tt.name, err)
		}
		ip.ctx.BackendRequest = req
		if err := ip.ProcessSetStatement(tt.stmt); err != nil {
			t.Errorf("%s: unexpected error returned: %s", tt.name, err)
		}
	}
}

func TestBlockStatement(t *testing.T) {
	var pass ast.Expression = &ast.Ident{
		Value: "pass",
		Meta:  &ast.Meta{},
	}
	tests := []struct {
		name           string
		scope          context.Scope
		stmts          []ast.Statement
		expected_state State
	}{
		{
			name:  "block statement with bare return",
			scope: context.RecvScope,
			stmts: []ast.Statement{
				&ast.ReturnStatement{},
			},
			expected_state: BARE_RETURN,
		},
		{
			name:  "nested block statement with return",
			scope: context.RecvScope,
			stmts: []ast.Statement{
				&ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.ReturnStatement{
							ReturnExpression: &pass,
						},
					},
				},
				&ast.ReturnStatement{},
			},
			expected_state: PASS,
		},
		{
			name:  "return in if statement should stop block execution",
			scope: context.RecvScope,
			stmts: []ast.Statement{
				&ast.IfStatement{
					Condition: &ast.Boolean{Value: true},
					Consequence: &ast.BlockStatement{
						Statements: []ast.Statement{
							&ast.ReturnStatement{},
						},
					},
				},
				&ast.ReturnStatement{
					ReturnExpression: &pass,
				},
			},
			expected_state: BARE_RETURN,
		},
	}

	for _, tt := range tests {
		ip := New(nil)

		ip.ctx = context.New()
		ip.SetScope(tt.scope)

		req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
		if err != nil {
			t.Errorf("%s: unexpected error returned: %s", tt.name, err)
		}
		ip.ctx.BackendRequest = req
		state, _, err := ip.ProcessBlockStatement(tt.stmts, DebugPass)
		if err != nil {
			t.Errorf("%s: unexpected error returned: %s", tt.name, err)
		}
		if state != tt.expected_state {
			t.Errorf("expect: \"%s\", actual: \"%s\"", tt.expected_state, state)
		}
	}
}

func TestFunctionCallStatement(t *testing.T) {
	tests := []struct {
		name       string
		vcl        string
		assertions map[string]value.Value
		isError    bool
	}{
		{
			name: "Function statement with builtin",
			vcl:  `sub vcl_recv { header.set(req, "foo", "bar"); }`,
			assertions: map[string]value.Value{
				"req.http.foo": &value.String{Value: "bar"},
			},
			isError: false,
		},
		{
			name: "Function statement with user defined subroutine",
			vcl: `sub bool_fn BOOL {
				set req.http.foo = "1";
				return true;
			}
			sub vcl_recv {
				set req.http.foo = "0";
				bool_fn(); }`,
			assertions: map[string]value.Value{
				"req.http.foo": &value.String{Value: "0"},
			},
			isError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertInterpreter(t, tt.vcl, context.RecvScope, tt.assertions, tt.isError)
		})
	}
}
