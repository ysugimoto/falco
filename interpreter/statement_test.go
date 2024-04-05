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
			expect: &value.IP{IsNotSet: true},
		},
		{
			name: "STRING value declaration",
			decl: &ast.DeclareStatement{
				Name:      &ast.Ident{Value: "var.foo"},
				ValueType: &ast.Ident{Value: "STRING"},
			},
			expect: &value.String{IsNotSet: true},
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
		err := ip.StackPointer.Locals.Declare(tt.decl.Name.Value, tt.decl.ValueType.Value)
		if err != nil {
			if !tt.isError {
				t.Errorf("%s: unexpected error returned: %s", tt.name, err)
			}
			continue
		}

		v, err := ip.StackPointer.Locals.Get(tt.decl.Name.Value)
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
		if err := ip.StackPointer.Locals.Declare("var.foo", "INTEGER"); err != nil {
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
		_, state, _, err := ip.ProcessBlockStatement(tt.stmts, DebugPass, false)
		if err != nil {
			t.Errorf("%s: unexpected error returned: %s", tt.name, err)
		}
		if state != tt.expected_state {
			t.Errorf("expect: \"%s\", actual: \"%s\"", tt.expected_state, state)
		}
	}
}

func TestBlockStatementWithReturnValue(t *testing.T) {
	var pass ast.Expression = &ast.Integer{
		Value: 1,
		Meta:  &ast.Meta{},
	}
	var invalid ast.Expression = &ast.String{
		Value: "invalid",
		Meta:  &ast.Meta{},
	}
	tests := []struct {
		name  string
		scope context.Scope
		stmts []ast.Statement
	}{
		{
			name:  "block statement will return value",
			scope: context.RecvScope,
			stmts: []ast.Statement{
				&ast.ReturnStatement{
					ReturnExpression: &pass,
				},
			},
		},
		{
			name:  "nested block statement with return value",
			scope: context.RecvScope,
			stmts: []ast.Statement{
				&ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.ReturnStatement{
							ReturnExpression: &pass,
						},
					},
				},
				&ast.ReturnStatement{
					ReturnExpression: &invalid,
				},
			},
		},
		{
			name:  "return in if statement should stop block execution and return value",
			scope: context.RecvScope,
			stmts: []ast.Statement{
				&ast.IfStatement{
					Condition: &ast.Boolean{Value: true},
					Consequence: &ast.BlockStatement{
						Statements: []ast.Statement{
							&ast.ReturnStatement{
								ReturnExpression: &pass,
							},
						},
					},
				},
				&ast.ReturnStatement{
					ReturnExpression: &invalid,
				},
			},
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
		val, state, _, err := ip.ProcessBlockStatement(tt.stmts, DebugPass, true)
		if err != nil {
			t.Errorf("%s: unexpected error returned: %s", tt.name, err)
		}
		if state != NONE {
			t.Errorf("Expected return value, state %s returned", state)
		}
		if v, ok := val.(*value.Integer); !ok {
			t.Errorf("(%s) block statement should return INTEGER, returns %s", tt.name, val.Type())
		} else if v.Value != 1 {
			t.Errorf("(%s) expect: \"%d\", actual: \"%d\"", tt.name, 1, v.Value)
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

func TestIfStatement(t *testing.T) {
	tests := []struct {
		name       string
		vcl        string
		assertions map[string]value.Value
		isError    bool
	}{
		{
			name: "Inverse string condition (empty)",
			vcl: `
			sub vcl_recv {
				declare local var.N BOOL;
				declare local var.S STRING;
				set var.S = "";
				if (!var.S) {
					set var.N = true;
				} else {
					set var.N = false;
				}
				header.set(req, "foo", var.N);
			}`,
			assertions: map[string]value.Value{
				"req.http.foo": &value.String{Value: "0"},
			},
			isError: false,
		},
		{
			name: "Inverse string condition (not set)",
			vcl: `
			sub vcl_recv {
				declare local var.N BOOL;
				declare local var.S STRING;
				if (!var.S) {
					set var.N = true;
				} else {
					set var.N = false;
				}
				header.set(req, "foo", var.N);
			}`,
			assertions: map[string]value.Value{
				"req.http.foo": &value.String{Value: "1"},
			},
			isError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertInterpreter(t, tt.vcl, context.RecvScope, tt.assertions, tt.isError)
		})
	}
}

func TestSwitchStatement(t *testing.T) {
	tests := []struct {
		name       string
		vcl        string
		assertions map[string]value.Value
		isError    bool
	}{
		{
			name: "String control value",
			vcl: `
			sub vcl_recv {
				set req.http.control = "2";
				switch (req.http.control) {
				case "1":
					set req.http.case = "1";
					break;
				case "2":
					set req.http.case = "2";
					break;
				}
			}`,
			assertions: map[string]value.Value{
				"req.http.case": &value.String{Value: "2"},
			},
			isError: false,
		},
		{
			name: "Integer control value",
			vcl: `
			sub vcl_recv {
				declare local var.control INTEGER;
				set var.control = 2;
				switch (var.control) {
				case "1":
					set req.http.case = "1";
					break;
				case "2":
					set req.http.case = "2";
					break;
				}
			}`,
			assertions: map[string]value.Value{
				"req.http.case": &value.String{Value: "2"},
			},
			isError: false,
		},
		{
			name: "Bool control value",
			vcl: `
			sub vcl_recv {
				declare local var.control BOOL;
				set var.control = true;
				switch (var.control) {
				case "0":
					set req.http.case = "0";
					break;
				case "1":
					set req.http.case = "1";
					break;
				}
			}`,
			assertions: map[string]value.Value{
				"req.http.case": &value.String{Value: "1"},
			},
			isError: false,
		},
		{
			name: "Backend control value",
			vcl: `
			sub vcl_recv {
				switch (req.backend) {
				case "test":
					set req.http.case = "0";
					break;
				case "example":
					set req.http.case = "1";
					break;
				}
			}`,
			assertions: map[string]value.Value{
				"req.http.case": &value.String{Value: "1"},
			},
			isError: false,
		},
		{
			name: "Float control value",
			vcl: `
			sub vcl_recv {
				declare local var.control FLOAT;
				set var.control = 1.03;
				switch (var.control) {
				case "0.000":
					set req.http.case = "0";
					break;
				case "1.030":
					set req.http.case = "1";
					break;
				}
			}`,
			assertions: map[string]value.Value{
				"req.http.case": &value.String{Value: "1"},
			},
			isError: false,
		},
		{
			name: "IP control value",
			vcl: `
			sub vcl_recv {
				declare local var.control IP;
				set var.control = "127.0.0.1";
				switch (var.control) {
				case "10.10.0.5":
					set req.http.case = "0";
					break;
				case "127.0.0.1":
					set req.http.case = "1";
					break;
				}
			}`,
			assertions: map[string]value.Value{
				"req.http.case": &value.String{Value: "1"},
			},
			isError: false,
		},
		{
			name: "RTIME control value",
			vcl: `
			sub vcl_recv {
				declare local var.control RTIME;
				set var.control = 5s;
				set req.http.case = "";
				switch (var.control) {
				case "2.000":
					set req.http.case = "0";
					break;
				case "5.000":
					set req.http.case = "1";
					break;
				}
			}`,
			assertions: map[string]value.Value{
				"req.http.case": &value.String{Value: "1"},
			},
			isError: false,
		},
		{
			name: "TIME control value",
			vcl: `
			sub vcl_recv {
				declare local var.control TIME;
				set var.control = std.time("Mon, 02 Jan 2006 22:04:05 GMT", now);
				switch (var.control) {
				case "Mon, 02 Jan 2006 22:04:06 GMT":
					set req.http.case = "0";
					break;
				case "Mon, 02 Jan 2006 22:04:05 GMT":
					set req.http.case = "1";
					break;
				}
			}`,
			assertions: map[string]value.Value{
				"req.http.case": &value.String{Value: "1"},
			},
			isError: false,
		},
		{
			name: "Builtin function call control value",
			vcl: `
			sub vcl_recv {
				switch (randomint(1,1)) {
				case "0":
					set req.http.case = "0";
					break;
				case "1":
					set req.http.case = "1";
					break;
				}
			}`,
			assertions: map[string]value.Value{
				"req.http.case": &value.String{Value: "1"},
			},
			isError: false,
		},
		{
			name: "User defined function call control value",
			vcl: `
			sub fn STRING { return "1"; }
			sub vcl_recv {
				switch (fn()) {
				case "0":
					set req.http.case = "0";
					break;
				case "1":
					set req.http.case = "1";
					break;
				}
			}`,
			assertions: map[string]value.Value{
				"req.http.case": &value.String{Value: "1"},
			},
			isError: false,
		},
		{
			name: "literal control value",
			vcl: `
			sub vcl_recv {
				switch ("1") {
				case "0":
					set req.http.case = "0";
					break;
				case "1":
					set req.http.case = "1";
					break;
				}
			}`,
			assertions: map[string]value.Value{
				"req.http.case": &value.String{Value: "1"},
			},
			isError: false,
		},
		{
			name: "regex case match",
			vcl: `
			sub vcl_recv {
				switch ("foo") {
				case ~"ar$":
					set req.http.case = "0";
					break;
				case ~"oo$":
					set req.http.case = "1";
					break;
				}
			}`,
			assertions: map[string]value.Value{
				"req.http.case": &value.String{Value: "1"},
			},
			isError: false,
		},
		{
			name: "case ordering",
			vcl: `
			sub vcl_recv {
				switch ("foo") {
				case "foo":
					set req.http.case = "0";
					break;
				case ~"oo$":
					set req.http.case = "1";
					break;
				}
			}`,
			assertions: map[string]value.Value{
				"req.http.case": &value.String{Value: "0"},
			},
			isError: false,
		},
		{
			name: "default case",
			vcl: `
			sub vcl_recv {
				switch ("foo") {
				case "bar":
					set req.http.case = "0";
					break;
				case ~"az$":
					set req.http.case = "1";
					break;
				default:
					set req.http.case = "2";
					break;
				}
			}`,
			assertions: map[string]value.Value{
				"req.http.case": &value.String{Value: "2"},
			},
			isError: false,
		},
		{
			name: "fallthrough case",
			vcl: `
			sub vcl_recv {
				switch ("baz") {
				case "bar":
					set req.http.case = "0";
					break;
				case ~"az$":
					set req.http.case = "1";
					set req.http.fallthrough = "1";
					fallthrough;
				case "foo":
					set req.http.case = "2";
					break;
				}
			}`,
			assertions: map[string]value.Value{
				"req.http.case":        &value.String{Value: "2"},
				"req.http.fallthrough": &value.String{Value: "1"},
			},
			isError: false,
		},
		{
			name: "return in fallthrough case",
			vcl: `
			sub vcl_recv {
				switch ("baz") {
				case "bar":
					set req.http.case = "0";
					break;
				case ~"az$":
					set req.http.case = "1";
					set req.http.fallthrough = "1";
					return (pass);
					fallthrough;
				case "foo":
					set req.http.case = "2";
					break;
				}
			}`,
			assertions: map[string]value.Value{
				"req.http.case":        &value.String{Value: "1"},
				"req.http.fallthrough": &value.String{Value: "1"},
			},
			isError: false,
		},
		{
			name: "ID control value",
			vcl: `
			table foo {}
			sub vcl_recv {
				switch (foo) {
				case "1":
					break;
				}
			}`,
			isError: true,
		},
		{
			name: "user defined function with non-string return type control value",
			vcl: `
			sub string_fn INTEGER { return 1; }
			sub vcl_recv {
				switch (string_fn()) {
				case "1":
					break;
				}
			}`,
			isError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertInterpreter(t, tt.vcl, context.RecvScope, tt.assertions, tt.isError)
		})
	}
}
