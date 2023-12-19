package interpreter

import (
	"testing"
	"time"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/token"
)

func TestPrefixExpression(t *testing.T) {

	t.Run("Bang prefix expression", func(t *testing.T) {
		tests := []struct {
			name          string
			expression    *ast.PrefixExpression
			expect        value.Value
			isError       bool
			withCondition bool
		}{
			{
				name: "inverse boolean",
				expression: &ast.PrefixExpression{
					Operator: "!",
					Right: &ast.Boolean{
						Value: true,
					},
					Meta: &ast.Meta{
						Token: token.Token{Type: token.NOT},
					},
				},
				expect: &value.Boolean{
					Value: false,
				},
			},
			{
				name: "inverse string error",
				expression: &ast.PrefixExpression{
					Operator: "!",
					Right: &ast.String{
						Value: "foo",
					},
					Meta: &ast.Meta{
						Token: token.Token{Type: token.NOT},
					},
				},
				isError: true,
			},
			{
				name: "inverse string inside condition",
				expression: &ast.PrefixExpression{
					Operator: "!",
					Right: &ast.String{
						Value: "foo",
					},
					Meta: &ast.Meta{
						Token: token.Token{Type: token.NOT},
					},
				},
				expect: &value.Boolean{
					Value: false,
				},
				withCondition: true,
			},
			{
				name: "inverse empty string inside condition",
				expression: &ast.PrefixExpression{
					Operator: "!",
					Right: &ast.String{
						Value: "",
					},
					Meta: &ast.Meta{
						Token: token.Token{Type: token.NOT},
					},
				},
				expect: &value.Boolean{
					Value: true,
				},
				withCondition: true,
			},
		}

		for _, tt := range tests {
			ip := New(nil)
			value, err := ip.ProcessPrefixExpression(tt.expression, tt.withCondition)
			if tt.isError {
				if err == nil {
					t.Errorf("%s expects error but non-nil", tt.name)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s unexpected error: %s", tt.name, err)
				continue
			}
			assertValue(t, tt.name, tt.expect, value)
		}
	})

	t.Run("Minus prefix expression", func(t *testing.T) {
		tests := []struct {
			name       string
			expression *ast.PrefixExpression
			expect     value.Value
			isError    bool
		}{
			{
				name: "minus integer",
				expression: &ast.PrefixExpression{
					Operator: "-",
					Right: &ast.Integer{
						Value: 100,
					},
					Meta: &ast.Meta{
						Token: token.Token{Type: token.MINUS},
					},
				},
				expect: &value.Integer{
					Value:   -100,
					Literal: true,
				},
			},
			{
				name: "minus float",
				expression: &ast.PrefixExpression{
					Operator: "-",
					Right: &ast.Float{
						Value: 100.0,
					},
					Meta: &ast.Meta{
						Token: token.Token{Type: token.MINUS},
					},
				},
				expect: &value.Float{
					Value:   -100.0,
					Literal: true,
				},
			},
			{
				name: "minus rtime",
				expression: &ast.PrefixExpression{
					Operator: "-",
					Right: &ast.RTime{
						Value: "1d",
					},
					Meta: &ast.Meta{
						Token: token.Token{Type: token.MINUS},
					},
				},
				expect: &value.RTime{
					Value:   -24 * time.Hour,
					Literal: true,
				},
			},
			{
				name: "minus error",
				expression: &ast.PrefixExpression{
					Operator: "-",
					Right: &ast.Boolean{
						Value: true,
					},
					Meta: &ast.Meta{
						Token: token.Token{Type: token.MINUS},
					},
				},
				isError: true,
			},
		}

		for _, tt := range tests {
			ip := New(nil)
			value, err := ip.ProcessPrefixExpression(tt.expression, false)
			if tt.isError {
				if err == nil {
					t.Errorf("%s expects error but non-nil", tt.name)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s unexpected error: %s", tt.name, err)
				continue
			}
			assertValue(t, tt.name, tt.expect, value)
		}
	})
}

func TestGroupedExpression(t *testing.T) {

	t.Run("Single expression", func(t *testing.T) {
		tests := []struct {
			name       string
			expression *ast.GroupedExpression
			expect     value.Value
			isError    bool
		}{
			{
				name: "minus integer",
				expression: &ast.GroupedExpression{
					Right: &ast.Integer{
						Value: 100,
					},
				},
				expect: &value.Integer{
					Value:   100,
					Literal: true,
				},
			},
			{
				name: "bang prefix should be boolean",
				expression: &ast.GroupedExpression{
					Right: &ast.PrefixExpression{
						Operator: "!",
						Right: &ast.String{
							Value: "",
						},
					},
				},
				expect: &value.Boolean{
					Value: true,
				},
			},
		}

		for _, tt := range tests {
			ip := New(nil)
			value, err := ip.ProcessGroupedExpression(tt.expression)
			if tt.isError {
				if err == nil {
					t.Errorf("%s expects error but non-nil", tt.name)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s unexpected error: %s", tt.name, err)
				continue
			}
			assertValue(t, tt.name, tt.expect, value)
		}
	})
}

func TestProcessExpression(t *testing.T) {
	tests := []struct {
		name       string
		vcl        string
		assertions map[string]value.Value
		isError    bool
	}{
		{
			name: "If expression (consequence)",
			vcl:  `sub vcl_recv { set req.http.Foo = if(req.http.Bar, "yes", "no"); }`,
			assertions: map[string]value.Value{
				"req.http.Foo": &value.String{Value: "no"},
			},
			isError: false,
		},
		{
			name: "If expression (alternative)",
			vcl:  `sub vcl_recv { set req.http.Foo = if(!req.http.Bar, "yes", "no"); }`,
			assertions: map[string]value.Value{
				"req.http.Foo": &value.String{Value: "yes"},
			},
			isError: false,
		},
		{
			name: "Set header to string literal",
			vcl:  `sub vcl_recv { set req.http.Foo = "yes"; }`,
			assertions: map[string]value.Value{
				"req.http.Foo": &value.String{Value: "yes"},
			},
			isError: false,
		},
		{
			name: "Set header to req.backend",
			vcl:  `sub vcl_recv { set req.http.Foo = req.backend; }`,
			assertions: map[string]value.Value{
				"req.http.Foo": &value.String{Value: "example"},
			},
			isError: false,
		},
		{
			name: "Set variable to backend",
			vcl: `sub vcl_recv {
				declare local var.backend STRING;
				set var.backend = req.backend;
				set req.http.Foo = var.backend;
			}`,
			assertions: map[string]value.Value{
				"req.http.Foo": &value.String{Value: "example"},
			},
			isError: false,
		},
		{
			name: "Set header to backend literal causes error",
			vcl:  `sub vcl_recv { set req.http.Foo = example; }`,
			assertions: map[string]value.Value{
				"req.http.Foo": &value.String{Value: ""},
			},
			isError: true,
		},
		{
			name: "Set integer variable to float literal causes error",
			vcl: `sub vcl_recv {
				declare local var.time TIME;
				set var.time = 1.2;
			}`,
			assertions: map[string]value.Value{},
			isError:    true,
		},
		{
			name: "Function call expression with call to header.get",
			vcl: `sub vcl_recv {
				set req.http.Foo2 = "yes";
				set req.http.Foo = header.get(req, "Foo2");
			}`,
			assertions: map[string]value.Value{
				"req.http.Foo": &value.String{Value: "yes"},
			},
			isError: false,
		},
		{
			name: "User defined function call expression",
			vcl: `sub bool_fn BOOL { return true; }
				sub vcl_recv {
					set req.http.foo = bool_fn();
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
