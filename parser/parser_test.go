package parser

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/token"
)

var T = token.Token{}

func assert(t *testing.T, actual, expect interface{}) {

	if diff := cmp.Diff(expect, actual,
		// Meta structs ignores Token info
		cmpopts.IgnoreFields(ast.Comment{}, "Token"),
		cmpopts.IgnoreFields(ast.Meta{}, "Token"),
		cmpopts.IgnoreFields(ast.Operator{}),

		// VCL type struct ignores Meta info
		cmpopts.IgnoreFields(ast.Ident{}),
		cmpopts.IgnoreFields(ast.Boolean{}),
		cmpopts.IgnoreFields(ast.Integer{}),
		cmpopts.IgnoreFields(ast.IP{}),
		cmpopts.IgnoreFields(ast.String{}),
		cmpopts.IgnoreFields(ast.Float{}),
		cmpopts.IgnoreFields(ast.RTime{}),

		cmpopts.IgnoreFields(ast.AclDeclaration{}),
		cmpopts.IgnoreFields(ast.AclCidr{}),
		cmpopts.IgnoreFields(ast.BackendDeclaration{}),
		cmpopts.IgnoreFields(ast.BackendProperty{}),
		cmpopts.IgnoreFields(ast.BackendProbeObject{}),
		cmpopts.IgnoreFields(ast.ImportStatement{}),
		cmpopts.IgnoreFields(ast.IncludeStatement{}),
		cmpopts.IgnoreFields(ast.DirectorDeclaration{}),
		cmpopts.IgnoreFields(ast.DirectorProperty{}),
		cmpopts.IgnoreFields(ast.DirectorBackendObject{}),
		cmpopts.IgnoreFields(ast.TableDeclaration{}),
		cmpopts.IgnoreFields(ast.TableProperty{}),
		cmpopts.IgnoreFields(ast.SubroutineDeclaration{}),
		cmpopts.IgnoreFields(ast.DeclareStatement{}),
		cmpopts.IgnoreFields(ast.BlockStatement{}),
		cmpopts.IgnoreFields(ast.SetStatement{}),
		cmpopts.IgnoreFields(ast.InfixExpression{}),
		cmpopts.IgnoreFields(ast.PrefixExpression{}),
		cmpopts.IgnoreFields(ast.GroupedExpression{}),
		cmpopts.IgnoreFields(ast.IfStatement{}, "AlternativeComments"),
		cmpopts.IgnoreFields(ast.UnsetStatement{}),
		cmpopts.IgnoreFields(ast.AddStatement{}),
		cmpopts.IgnoreFields(ast.CallStatement{}),
		cmpopts.IgnoreFields(ast.ErrorStatement{}),
		cmpopts.IgnoreFields(ast.LogStatement{}),
		cmpopts.IgnoreFields(ast.ReturnStatement{}),
		cmpopts.IgnoreFields(ast.SyntheticStatement{}),
		cmpopts.IgnoreFields(ast.SyntheticBase64Statement{}),
		cmpopts.IgnoreFields(ast.IfExpression{}),
		cmpopts.IgnoreFields(ast.FunctionCallExpression{}),
		cmpopts.IgnoreFields(ast.RestartStatement{}),
		cmpopts.IgnoreFields(ast.EsiStatement{}),
	); diff != "" {
		t.Errorf("Assertion error: diff=%s", diff)
	}
}

// Utility
func comments(c ...string) ast.Comments {
	cs := ast.Comments{}
	for i := range c {
		cs = append(cs, &ast.Comment{
			Value: c[i],
		})
	}
	return cs
}

func TestParseStringConcatExpression(t *testing.T) {
	input := `// Subroutine
sub vcl_recv {
	declare local var.S STRING;
	set var.S = "foo" "bar" + "baz";
}`
	_, err := New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Error(err)
	}
}

func TestCommentInInfixExpression(t *testing.T) {
	input := `
sub vcl_recv {
	if (
		req.http.Host &&
		# Some comment here inside infix expressions
		req.http.Foo == "bar"
	) {
		set req.http.Host = "bar";
	}
}`
	_, err := New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Errorf("%+v", err)
	}
}

func TestSetStatementWithGroupedExpression(t *testing.T) {
	input := `
sub vcl_recv {
	set var.Bool = (var.IsOk && var.IsNg);
}`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.SubroutineDeclaration{
				Meta: ast.New(T, 0),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "vcl_recv",
				},
				Block: &ast.BlockStatement{
					Meta: ast.New(T, 1),
					Statements: []ast.Statement{
						&ast.SetStatement{
							Meta: ast.New(T, 1),
							Ident: &ast.Ident{
								Meta:  ast.New(T, 1),
								Value: "var.Bool",
							},
							Operator: &ast.Operator{
								Meta:     ast.New(T, 1),
								Operator: "=",
							},
							Value: &ast.GroupedExpression{
								Meta: ast.New(T, 1),
								Right: &ast.InfixExpression{
									Meta: ast.New(T, 1),
									Left: &ast.Ident{
										Meta:  ast.New(T, 1),
										Value: "var.IsOk",
									},
									Operator: "&&",
									Right: &ast.Ident{
										Meta:  ast.New(T, 1),
										Value: "var.IsNg",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	vcl, err := New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Errorf("%+v", err)
	}
	assert(t, vcl, expect)
}

func TestErrorStatementWithoutArgument(t *testing.T) {
	input := `
sub vcl_recv {
	error;
}`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.SubroutineDeclaration{
				Meta: ast.New(T, 0),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "vcl_recv",
				},
				Block: &ast.BlockStatement{
					Meta: ast.New(T, 1),
					Statements: []ast.Statement{
						&ast.ErrorStatement{
							Meta:     ast.New(T, 1),
							Code:     nil,
							Argument: nil,
						},
					},
				},
			},
		},
	}
	vcl, err := New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Errorf("%+v", err)
	}
	assert(t, vcl, expect)
}
