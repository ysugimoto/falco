package interpreter

import (
	"testing"
	"time"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/simulator/variable"
)

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
