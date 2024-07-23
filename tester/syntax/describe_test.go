package syntax

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/token"
)

func meta(nest, prevLine int, leading, infix, trailing string) *ast.Meta {
	m := &ast.Meta{
		Token:              token.Token{},
		Nest:               nest,
		PreviousEmptyLines: prevLine,
		Leading:            ast.Comments{},
		Infix:              ast.Comments{},
		Trailing:           ast.Comments{},
	}
	if leading != "" {
		m.Leading = ast.Comments{&ast.Comment{Value: leading}}
	}
	if infix != "" {
		m.Infix = ast.Comments{&ast.Comment{Value: infix}}
	}
	if trailing != "" {
		m.Trailing = ast.Comments{&ast.Comment{Value: trailing}}
	}

	return m
}

func TestDescribeFullSyntax(t *testing.T) {
	input := `// Leading comment
describe foo {
	// before leading
	before_recv /* before infix */ {
		set req.http.TestingState = "before_recv";
	} // before trailing

	// before leading
	before_fetch /* before infix */ {
		set req.http.TestingState = "before_fetch";
	} // before trailing

	// after leading
	after_recv /* after infix */ {
		set req.http.TestingState = "after_recv";
	} // after trailing

	// after leading
	after_fetch /* after infix */ {
		set req.http.TestingState = "after_fetch";
	} // after trailing

	sub test_foo_recv {
		set req.http.Bar = "baz";
	}
} // Trailing comment

sub test_recv {}
`

	expect := &ast.VCL{
		Statements: []ast.Statement{
			&DescribeStatement{
				Meta: meta(0, 0, "// Leading comment", "", "// Trailing comment"),
				Name: &ast.Ident{
					Meta:  meta(0, 0, "", "", ""),
					Value: "foo",
				},
				Befores: map[string]*HookStatement{
					"before_recv": {
						Meta: meta(1, 0, "// before leading", "/* before infix */", ""),
						Block: &ast.BlockStatement{
							Meta: meta(2, 0, "", "", "// before trailing"),
							Statements: []ast.Statement{
								&ast.SetStatement{
									Meta: meta(2, 0, "", "", ""),
									Ident: &ast.Ident{
										Meta:  meta(2, 0, "", "", ""),
										Value: "req.http.TestingState",
									},
									Operator: &ast.Operator{
										Meta:     meta(2, 0, "", "", ""),
										Operator: "=",
									},
									Value: &ast.String{
										Meta:  meta(2, 0, "", "", ""),
										Value: "before_recv",
									},
								},
							},
						},
					},
					"before_fetch": {
						Meta: meta(1, 0, "// before leading", "/* before infix */", ""),
						Block: &ast.BlockStatement{
							Meta: meta(2, 0, "", "", "// before trailing"),
							Statements: []ast.Statement{
								&ast.SetStatement{
									Meta: meta(2, 0, "", "", ""),
									Ident: &ast.Ident{
										Meta:  meta(2, 0, "", "", ""),
										Value: "req.http.TestingState",
									},
									Operator: &ast.Operator{
										Meta:     meta(2, 0, "", "", ""),
										Operator: "=",
									},
									Value: &ast.String{
										Meta:  meta(2, 0, "", "", ""),
										Value: "before_fetch",
									},
								},
							},
						},
					},
				},
				Afters: map[string]*HookStatement{
					"after_recv": {
						Meta: meta(1, 0, "// after leading", "/* after infix */", ""),
						Block: &ast.BlockStatement{
							Meta: meta(2, 0, "", "", "// after trailing"),
							Statements: []ast.Statement{
								&ast.SetStatement{
									Meta: meta(2, 0, "", "", ""),
									Ident: &ast.Ident{
										Meta:  meta(2, 0, "", "", ""),
										Value: "req.http.TestingState",
									},
									Operator: &ast.Operator{
										Meta:     meta(2, 0, "", "", ""),
										Operator: "=",
									},
									Value: &ast.String{
										Meta:  meta(2, 0, "", "", ""),
										Value: "after_recv",
									},
								},
							},
						},
					},
					"after_fetch": {
						Meta: meta(1, 0, "// after leading", "/* after infix */", ""),
						Block: &ast.BlockStatement{
							Meta: meta(2, 0, "", "", "// after trailing"),
							Statements: []ast.Statement{
								&ast.SetStatement{
									Meta: meta(2, 0, "", "", ""),
									Ident: &ast.Ident{
										Meta:  meta(2, 0, "", "", ""),
										Value: "req.http.TestingState",
									},
									Operator: &ast.Operator{
										Meta:     meta(2, 0, "", "", ""),
										Operator: "=",
									},
									Value: &ast.String{
										Meta:  meta(2, 0, "", "", ""),
										Value: "after_fetch",
									},
								},
							},
						},
					},
				},
				Subroutines: []*ast.SubroutineDeclaration{
					{
						Meta: meta(1, 1, "", "", ""),
						Name: &ast.Ident{
							Meta:  meta(1, 0, "", "", ""),
							Value: "test_foo_recv",
						},
						Block: &ast.BlockStatement{
							Meta: meta(2, 0, "", "", ""),
							Statements: []ast.Statement{
								&ast.SetStatement{
									Meta: meta(2, 0, "", "", ""),
									Ident: &ast.Ident{
										Meta:  meta(2, 0, "", "", ""),
										Value: "req.http.Bar",
									},
									Operator: &ast.Operator{
										Meta:     meta(2, 0, "", "", ""),
										Operator: "=",
									},
									Value: &ast.String{
										Meta:  meta(2, 0, "", "", ""),
										Value: "baz",
									},
								},
							},
						},
					},
				},
			},
			&ast.SubroutineDeclaration{
				Meta: meta(0, 1, "", "", ""),
				Name: &ast.Ident{
					Meta:  meta(0, 0, "", "", ""),
					Value: "test_recv",
				},
				Block: &ast.BlockStatement{
					Meta:       meta(1, 0, "", "", ""),
					Statements: []ast.Statement{},
				},
			},
		},
	}

	vcl, err := parser.New(lexer.NewFromString(input), parser.WithCustomParser(CustomParsers()...)).ParseVCL()
	if err != nil {
		t.Errorf("%+v", err)
	}

	if diff := cmp.Diff(vcl, expect,
		cmpopts.IgnoreFields(ast.Meta{}, "Token", "ID"),
		cmpopts.IgnoreFields(ast.Comment{}, "Token", "PrefixedLineFeed", "PreviousEmptyLines"),
		cmpopts.IgnoreFields(ast.Ident{}),
		cmpopts.IgnoreFields(ast.String{}),
		cmpopts.IgnoreFields(ast.Operator{}),
		cmpopts.IgnoreUnexported(HookStatement{}),
	); diff != "" {
		t.Errorf("Assertion error: diff=%s", diff)
	}
}
