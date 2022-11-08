package interpreter

import (
	"testing"
	"time"

	"net/http"
	"net/http/httptest"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/simulator/context"
	"github.com/ysugimoto/falco/simulator/variable"
)

func assertInterpreter(t *testing.T, vcl string, assertions map[string]variable.Value) {
	p, err := parser.New(lexer.NewFromString(vcl)).ParseVCL()
	if err != nil {
		t.Errorf("VCL parsing error: %s", err)
		return
	}
	ctx, err := context.New(p)
	if err != nil {
		t.Errorf("Context creation error: %s", err)
		return
	}
	ip := New(ctx)
	if err := ip.Process(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "http://localhost", nil),
	); err != nil {
		t.Errorf("Interpreter process error: %s", err)
		return
	}

	for name, val := range assertions {
		v := ip.vars.Get(name)
		if v == nil {
			t.Errorf("Variable %s is nil", name)
			return
		}
		if v.Value == nil {
			t.Errorf("Variable %s value is nil", name)
			return
		}
		if v.Value.Type() != val.Type() {
			t.Errorf("Variable %s type unmatch, expect %s, got %s", name, val.Type(), v.Value.Type())
			return
		}
		if v.Value.String() != val.String() {
			t.Errorf("Variable %s value unmatch, expect %v, got %v", name, val.String(), v.Value.String())
			return
		}
	}
}

func assertValue(t *testing.T, name string, expect, actual variable.Value) {
	if expect.Type() != actual.Type() {
		t.Errorf("%s type unmatch, expect %s, got %s", name, expect.Type(), actual.Type())
		return
	}
	if expect.String() != actual.String() {
		t.Errorf("%s value unmatch, expect %v, got %v", name, expect.String(), actual.String())
		return
	}
}

func TestPrefixExpression(t *testing.T) {

	t.Run("Bang prefix expression", func(t *testing.T) {
		tests := []struct{
			name string
			expression *ast.PrefixExpression
			expect variable.Value
			isError bool
			withCondition bool
		}{
			{
				name: "inverse boolean",
				expression: &ast.PrefixExpression{
					Operator: "!",
					Right: &ast.Boolean{
						Value: true,
					},
				},
				expect: &variable.Boolean{
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
				},
				expect: &variable.Boolean{
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
				},
				expect: &variable.Boolean{
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
		tests := []struct{
			name string
			expression *ast.PrefixExpression
			expect variable.Value
			isError bool
		}{
			{
				name: "minus integer",
				expression: &ast.PrefixExpression{
					Operator: "-",
					Right: &ast.Integer{
						Value: 100,
					},
				},
				expect: &variable.Integer{
					Value: -100,
				},
			},
			{
				name: "minus float",
				expression: &ast.PrefixExpression{
					Operator: "-",
					Right: &ast.Float{
						Value: 100.0,
					},
				},
				expect: &variable.Float{
					Value: -100.0,
				},
			},
			{
				name: "minus rtime",
				expression: &ast.PrefixExpression{
					Operator: "-",
					Right: &ast.RTime{
						Value: "1d",
					},
				},
				expect: &variable.RTime{
					Value: -24 * time.Hour,
				},
			},
			{
				name: "minus error",
				expression: &ast.PrefixExpression{
					Operator: "-",
					Right: &ast.Boolean{
						Value: true,
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
		tests := []struct{
			name string
			expression *ast.GroupedExpression
			expect variable.Value
			isError bool
		}{
			{
				name: "minus integer",
				expression: &ast.GroupedExpression{
					Right: &ast.Integer{
						Value: 100,
					},
				},
				expect: &variable.Integer{
					Value: 100,
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
				expect: &variable.Boolean{
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

func TestIfExpression(t *testing.T) {

	t.Run("Consequence", func(t *testing.T) {
		vcl := `
sub vcl_recv {
	set req.http.Foo = if(req.http.Bar, "yes", "no");
}`
		assertInterpreter(t, vcl, map[string]variable.Value{
			"req.http.Foo": &variable.String{ Value: "no" },
		})
	})

	t.Run("Alternative", func(t *testing.T) {
		vcl := `
sub vcl_recv {
	set req.http.Foo = if(!req.http.Bar, "yes", "no");
}`
		assertInterpreter(t, vcl, map[string]variable.Value{
			"req.http.Foo": &variable.String{ Value: "yes" },
		})
	})
}

func TestProcessExpression(t *testing.T) {
	vcl := `
sub vcl_recv {
	set req.http.Foo = "yes";
}`
	assertInterpreter(t, vcl, map[string]variable.Value{
		"req.http.Foo": &variable.String{ Value: "yes" },
	})
}
