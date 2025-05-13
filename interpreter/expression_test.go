package interpreter

import (
	"fmt"
	ghttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/http"
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
					Value: false,
				},
				withCondition: true,
			},
		}

		for _, tt := range tests {
			ip := New(nil)
			opt := &ExpressionOption{
				condition: tt.withCondition,
			}
			value, err := ip.ProcessPrefixExpression(tt.expression, opt)
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
			opt := &ExpressionOption{
				condition: false,
			}
			value, err := ip.ProcessPrefixExpression(tt.expression, opt)
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
					Value: false,
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
				"req.http.Foo": &value.String{IsNotSet: true},
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

func TestProcessStringConcat(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name       string
		vcl        string
		assertions map[string]value.Value
		isError    bool
	}{
		{
			name: "normal concatenation",
			vcl:  `sub vcl_recv { set req.http.Foo = "foo" + "bar" "baz"; }`,
			assertions: map[string]value.Value{
				"req.http.Foo": &value.String{Value: "foobarbaz"},
			},
		},
		{
			name:    "invalid group expression",
			vcl:     `sub vcl_recv { set req.http.Foo = ("foo" + "bar") + "baz"; }`,
			isError: true,
		},
		{
			name:    "invalid group expression 2",
			vcl:     `sub vcl_recv { set req.http.Foo = "foo" + (now + 5m) + "; bar"; }`,
			isError: true,
		},
		{
			name:    "INTEGER concatenation",
			vcl:     `sub vcl_recv { set req.http.Foo = "foo" + 1; }`,
			isError: true,
		},
		{
			name:    "INTEGER concatenation 2",
			vcl:     `sub vcl_recv { set req.http.Foo = "foo" + -1; }`,
			isError: true,
		},
		{
			name:    "FLOAT concatenation",
			vcl:     `sub vcl_recv { set req.http.Foo = "foo" + 0.5; }`,
			isError: true,
		},
		{
			name:    "RTIME concatenation",
			vcl:     `sub vcl_recv { set req.http.Foo = "foo" + 6s; }`,
			isError: true,
		},
		{
			name: "TIME concatenation",
			vcl:  `sub vcl_recv { set req.http.Foo = "foo" + now; }`,
			assertions: map[string]value.Value{
				"req.http.Foo": &value.String{Value: "foo" + now.Format(http.TimeFormat)},
			},
		},
		{
			name:    "FunctionCall expression concatenation with not string",
			vcl:     `sub vcl_recv { set req.http.Foo = "foo" + std.atoi("foo"); }`,
			isError: true,
		},
		{
			name: "FunctionCall expression concatenation with string",
			vcl:  `sub vcl_recv { set req.http.Foo = "foo" + std.itoa(10); }`,
			assertions: map[string]value.Value{
				"req.http.Foo": &value.String{Value: "foo10"},
			},
		},
		{
			name: "if expression concatenation, returns string",
			vcl:  `sub vcl_recv { set req.http.Foo = "foo" + if(req.http.Bar, "1", "0"); }`,
			assertions: map[string]value.Value{
				"req.http.Foo": &value.String{Value: "foo0"},
			},
		},
		{
			name:    "if expression concatenation, returns not string",
			vcl:     `sub vcl_recv { set req.http.Foo = "foo" + if(req.http.Bar, 1, 0); }`,
			isError: true,
		},
		{
			name:    "prefix expression concatenation",
			vcl:     `sub vcl_recv { set req.http.Foo = "foo" + !req.http.Bar; }`,
			isError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertInterpreter(t, tt.vcl, context.RecvScope, tt.assertions, tt.isError)
		})
	}
}

// https://github.com/ysugimoto/falco/issues/360
func TestProcessStringConcatIssue360(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name       string
		vcl        string
		assertions map[string]value.Value
		isError    bool
	}{
		{
			name: "concat RTIME to left string",
			vcl: `
 sub vcl_deliver {
 	#FASTLY deliver
 	set resp.http.Set-Cookie = "test=abc; domain=fiddle.fastly.dev; path=/; expires=" 5m ";";
 }
 `,
			isError: true,
		},
		{
			name: "concat RTIME to left string with explicit plus sign",
			vcl: `
  sub vcl_deliver {
  	#FASTLY deliver
  	set resp.http.Set-Cookie = "test=abc; domain=fiddle.fastly.dev; path=/; expires=" + 5m ";";
  }
  `,
			isError: true,
		},
		{
			name: "concat RTIME to left TIME with explicit plus sign",
			vcl: `
  sub vcl_deliver {
  	#FASTLY deliver
  	set resp.http.Set-Cookie = "test=abc; domain=fiddle.fastly.dev; path=/; expires=" now + 5m ";";
  }
  `,
			assertions: map[string]value.Value{
				"resp.http.Set-Cookie": &value.String{
					Value: fmt.Sprintf(
						`test=abc; domain=fiddle.fastly.dev; path=/; expires=%s;`,
						now.Add(5*time.Minute).Format(http.TimeFormat),
					),
				},
			},
		},
		{
			name: "concat RTIME to left TIME without plus sign",
			vcl: `
   sub vcl_deliver {
   	#FASTLY deliver
   	set resp.http.Set-Cookie = "test=abc; domain=fiddle.fastly.dev; path=/; expires=" now 5m ";";
   }
   `,
			isError: true,
		},
		{
			name: "concat RTIME variable to left TIME with plus sign",
			vcl: `
  sub vcl_deliver {
  	#FASTLY deliver
  	declare local var.R RTIME;
  	set var.R = 5m;
  	set resp.http.Set-Cookie = "test=abc; domain=fiddle.fastly.dev; path=/; expires=" now + var.R ";";
  }
   `,
			isError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertInterpreter(t, tt.vcl, context.DeliverScope, tt.assertions, tt.isError)
		})
	}
}

func TestIsNotSetSeriesCheck(t *testing.T) {
	tests := []struct {
		name   string
		series []*series
		expect bool
	}{
		{
			name: "single notset variable series",
			series: []*series{
				{
					Expression: &ast.Ident{
						Value: "var.NS",
					},
				},
			},
			expect: true,
		},
		{
			name: "single variable series",
			series: []*series{
				{
					Expression: &ast.Ident{
						Value: "var.S",
					},
				},
			},
			expect: false,
		},
		{
			name: "double notset variable series",
			series: []*series{
				{
					Expression: &ast.Ident{
						Value: "var.NS",
					},
				},
				{
					Expression: &ast.Ident{
						Value: "req.http.Undefined",
					},
				},
			},
			expect: true,
		},
		{
			name: "either variable is set",
			series: []*series{
				{
					Expression: &ast.Ident{
						Value: "var.S",
					},
				},
				{
					Expression: &ast.Ident{
						Value: "req.http.Undefined",
					},
				},
			},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := New()
			i.ctx = context.New()
			i.ctx.Scope = context.RecvScope
			i.ctx.Request = http.WrapRequest(
				httptest.NewRequest(ghttp.MethodGet, "http://localhost:3124", nil),
			)
			i.SetScope(context.RecvScope)
			i.localVars.Declare("var.NS", "IP")
			i.localVars.Declare("var.S", "STRING")
			i.localVars.Set("var.S", "=", &value.String{Value: "S"})

			actual := i.isNotSetExpressionSeries(tt.series)
			if diff := cmp.Diff(tt.expect, actual); diff != "" {
				t.Errorf("result mismatch, diff=%s", diff)
			}
		})
	}
}
