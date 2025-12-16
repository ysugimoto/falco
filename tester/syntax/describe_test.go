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

func comments(c ...string) ast.Comments {
	cs := ast.Comments{}
	for i := range c {
		cs = append(cs, &ast.Comment{
			Value: c[i],
		})
	}
	return cs
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
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.Custom("DESCRIBE"),
						Literal:  "describe",
						Line:     2,
						Position: 1,
					},
					Nest:               0,
					PreviousEmptyLines: 0,
					Leading:            comments("// Leading comment"),
					Infix:              comments(),
					Trailing:           comments("// Trailing comment"),
					EndLine:            26,
					EndPosition:        1,
				},
				Name: &ast.Ident{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.IDENT,
							Literal:  "foo",
							Line:     2,
							Position: 10,
						},
						Nest:               0,
						PreviousEmptyLines: 0,
						Leading:            comments(),
						Infix:              comments(),
						Trailing:           comments(),
						EndLine:            2,
						EndPosition:        12,
					},
					Value: "foo",
				},
				Befores: map[string]*HookStatement{
					"before_recv": {
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.Custom("BEFORE_RECV"),
								Literal:  "before_recv",
								Line:     4,
								Position: 2,
							},
							Nest:               1,
							PreviousEmptyLines: 0,
							Leading:            comments("// before leading"),
							Infix:              comments("/* before infix */"),
							Trailing:           comments(),
							EndLine:            6,
							EndPosition:        2,
						},
						Block: &ast.BlockStatement{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.LEFT_BRACE,
									Literal:  "{",
									Line:     4,
									Position: 33,
								},
								Nest:               2,
								PreviousEmptyLines: 0,
								Leading:            comments(),
								Infix:              comments(),
								Trailing:           comments("// before trailing"),
								EndLine:            6,
								EndPosition:        2,
							},
							Statements: []ast.Statement{
								&ast.SetStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.SET,
											Literal:  "set",
											Line:     5,
											Position: 3,
										},
										Nest:               2,
										PreviousEmptyLines: 0,
										Leading:            comments(),
										Infix:              comments(),
										Trailing:           comments(),
										EndLine:            5,
										EndPosition:        43,
									},
									Ident: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.TestingState",
												Line:     5,
												Position: 7,
											},
											Nest:               2,
											PreviousEmptyLines: 0,
											Leading:            comments(),
											Infix:              comments(),
											Trailing:           comments(),
											EndLine:            5,
											EndPosition:        27,
										},
										Value: "req.http.TestingState",
									},
									Operator: &ast.Operator{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.ASSIGN,
												Literal:  "=",
												Line:     5,
												Position: 29,
											},
											Nest:               2,
											PreviousEmptyLines: 0,
											Leading:            comments(),
											Infix:              comments(),
											Trailing:           comments(),
											EndLine:            5,
											EndPosition:        29,
										},
										Operator: "=",
									},
									Value: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "before_recv",
												Line:     5,
												Position: 31,
											},
											Nest:               2,
											PreviousEmptyLines: 0,
											Leading:            comments(),
											Infix:              comments(),
											Trailing:           comments(),
											EndLine:            5,
											EndPosition:        43,
										},
										Value: "before_recv",
									},
								},
							},
						},
					},
					"before_fetch": {
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.Custom("BEFORE_FETCH"),
								Literal:  "before_fetch",
								Line:     9,
								Position: 2,
							},
							Nest:               1,
							PreviousEmptyLines: 0,
							Leading:            comments("// before leading"),
							Infix:              comments("/* before infix */"),
							Trailing:           comments(),
							EndLine:            11,
							EndPosition:        2,
						},
						Block: &ast.BlockStatement{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.LEFT_BRACE,
									Literal:  "{",
									Line:     9,
									Position: 34,
								},
								Nest:               2,
								PreviousEmptyLines: 0,
								Leading:            comments(),
								Infix:              comments(),
								Trailing:           comments("// before trailing"),
								EndLine:            11,
								EndPosition:        2,
							},
							Statements: []ast.Statement{
								&ast.SetStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.SET,
											Literal:  "set",
											Line:     10,
											Position: 3,
										},
										Nest:               2,
										PreviousEmptyLines: 0,
										Leading:            comments(),
										Infix:              comments(),
										Trailing:           comments(),
										EndLine:            10,
										EndPosition:        44,
									},
									Ident: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.TestingState",
												Line:     10,
												Position: 7,
											},
											Nest:               2,
											PreviousEmptyLines: 0,
											Leading:            comments(),
											Infix:              comments(),
											Trailing:           comments(),
											EndLine:            10,
											EndPosition:        27,
										},
										Value: "req.http.TestingState",
									},
									Operator: &ast.Operator{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.ASSIGN,
												Literal:  "=",
												Line:     10,
												Position: 29,
											},
											Nest:               2,
											PreviousEmptyLines: 0,
											Leading:            comments(),
											Infix:              comments(),
											Trailing:           comments(),
											EndLine:            10,
											EndPosition:        29,
										},
										Operator: "=",
									},
									Value: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "before_fetch",
												Line:     10,
												Position: 31,
											},
											Nest:               2,
											PreviousEmptyLines: 0,
											Leading:            comments(),
											Infix:              comments(),
											Trailing:           comments(),
											EndLine:            10,
											EndPosition:        44,
										},
										Value: "before_fetch",
									},
								},
							},
						},
					},
				},
				Afters: map[string]*HookStatement{
					"after_recv": {
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.Custom("AFTER_RECV"),
								Literal:  "after_recv",
								Line:     14,
								Position: 2,
							},
							Nest:               1,
							PreviousEmptyLines: 0,
							Leading:            comments("// after leading"),
							Infix:              comments("/* after infix */"),
							Trailing:           comments(),
							EndLine:            16,
							EndPosition:        2,
						},
						Block: &ast.BlockStatement{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.LEFT_BRACE,
									Literal:  "{",
									Line:     14,
									Position: 31,
								},
								Nest:               2,
								PreviousEmptyLines: 0,
								Leading:            comments(),
								Infix:              comments(),
								Trailing:           comments("// after trailing"),
								EndLine:            16,
								EndPosition:        2,
							},
							Statements: []ast.Statement{
								&ast.SetStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.SET,
											Literal:  "set",
											Line:     15,
											Position: 3,
										},
										Nest:               2,
										PreviousEmptyLines: 0,
										Leading:            comments(),
										Infix:              comments(),
										Trailing:           comments(),
										EndLine:            15,
										EndPosition:        42,
									},
									Ident: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.TestingState",
												Line:     15,
												Position: 7,
											},
											Nest:               2,
											PreviousEmptyLines: 0,
											Leading:            comments(),
											Infix:              comments(),
											Trailing:           comments(),
											EndLine:            15,
											EndPosition:        27,
										},
										Value: "req.http.TestingState",
									},
									Operator: &ast.Operator{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.ASSIGN,
												Literal:  "=",
												Line:     15,
												Position: 29,
											},
											Nest:               2,
											PreviousEmptyLines: 0,
											Leading:            comments(),
											Infix:              comments(),
											Trailing:           comments(),
											EndLine:            15,
											EndPosition:        29,
										},
										Operator: "=",
									},
									Value: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "after_recv",
												Line:     15,
												Position: 31,
											},
											Nest:               2,
											PreviousEmptyLines: 0,
											Leading:            comments(),
											Infix:              comments(),
											Trailing:           comments(),
											EndLine:            15,
											EndPosition:        42,
										},
										Value: "after_recv",
									},
								},
							},
						},
					},
					"after_fetch": {
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.Custom("AFTER_FETCH"),
								Literal:  "after_fetch",
								Line:     19,
								Position: 2,
							},
							Nest:               1,
							PreviousEmptyLines: 0,
							Leading:            comments("// after leading"),
							Infix:              comments("/* after infix */"),
							Trailing:           comments(),
							EndLine:            21,
							EndPosition:        2,
						},
						Block: &ast.BlockStatement{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.LEFT_BRACE,
									Literal:  "{",
									Line:     19,
									Position: 32,
								},
								Nest:               2,
								PreviousEmptyLines: 0,
								Leading:            comments(),
								Infix:              comments(),
								Trailing:           comments("// after trailing"),
								EndLine:            21,
								EndPosition:        2,
							},
							Statements: []ast.Statement{
								&ast.SetStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.SET,
											Literal:  "set",
											Line:     20,
											Position: 3,
										},
										Nest:               2,
										PreviousEmptyLines: 0,
										Leading:            comments(),
										Infix:              comments(),
										Trailing:           comments(),
										EndLine:            20,
										EndPosition:        43,
									},
									Ident: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.TestingState",
												Line:     20,
												Position: 7,
											},
											Nest:               2,
											PreviousEmptyLines: 0,
											Leading:            comments(),
											Infix:              comments(),
											Trailing:           comments(),
											EndLine:            20,
											EndPosition:        27,
										},
										Value: "req.http.TestingState",
									},
									Operator: &ast.Operator{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.ASSIGN,
												Literal:  "=",
												Line:     20,
												Position: 29,
											},
											Nest:               2,
											PreviousEmptyLines: 0,
											Leading:            comments(),
											Infix:              comments(),
											Trailing:           comments(),
											EndLine:            20,
											EndPosition:        29,
										},
										Operator: "=",
									},
									Value: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "after_fetch",
												Line:     20,
												Position: 31,
											},
											Nest:               2,
											PreviousEmptyLines: 0,
											Leading:            comments(),
											Infix:              comments(),
											Trailing:           comments(),
											EndLine:            20,
											EndPosition:        43,
										},
										Value: "after_fetch",
									},
								},
							},
						},
					},
				},
				Subroutines: []*ast.SubroutineDeclaration{
					{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.SUBROUTINE,
								Literal:  "sub",
								Line:     23,
								Position: 2,
							},
							Nest:               1,
							PreviousEmptyLines: 1,
							Leading:            comments(),
							Infix:              comments(),
							Trailing:           comments(),
							EndLine:            25,
							EndPosition:        2,
						},
						Name: &ast.Ident{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.IDENT,
									Literal:  "test_foo_recv",
									Line:     23,
									Position: 6,
								},
								Nest:               1,
								PreviousEmptyLines: 0,
								Leading:            comments(),
								Infix:              comments(),
								Trailing:           comments(),
								EndLine:            23,
								EndPosition:        18,
							},
							Value: "test_foo_recv",
						},
						Block: &ast.BlockStatement{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.LEFT_BRACE,
									Literal:  "{",
									Line:     23,
									Position: 20,
								},
								Nest:               2,
								PreviousEmptyLines: 0,
								Leading:            comments(),
								Infix:              comments(),
								Trailing:           comments(),
								EndLine:            25,
								EndPosition:        2,
							},
							Statements: []ast.Statement{
								&ast.SetStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.SET,
											Literal:  "set",
											Line:     24,
											Position: 3,
										},
										Nest:               2,
										PreviousEmptyLines: 0,
										Leading:            comments(),
										Infix:              comments(),
										Trailing:           comments(),
										EndLine:            24,
										EndPosition:        26,
									},
									Ident: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.Bar",
												Line:     24,
												Position: 7,
											},
											Nest:               2,
											PreviousEmptyLines: 0,
											Leading:            comments(),
											Infix:              comments(),
											Trailing:           comments(),
											EndLine:            24,
											EndPosition:        18,
										},
										Value: "req.http.Bar",
									},
									Operator: &ast.Operator{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.ASSIGN,
												Literal:  "=",
												Line:     24,
												Position: 20,
											},
											Nest:               2,
											PreviousEmptyLines: 0,
											Leading:            comments(),
											Infix:              comments(),
											Trailing:           comments(),
											EndLine:            24,
											EndPosition:        20,
										},
										Operator: "=",
									},
									Value: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "baz",
												Line:     24,
												Position: 22,
											},
											Nest:               2,
											PreviousEmptyLines: 0,
											Leading:            comments(),
											Infix:              comments(),
											Trailing:           comments(),
											EndLine:            24,
											EndPosition:        26,
										},
										Value: "baz",
									},
								},
							},
						},
					},
				},
			},
			&ast.SubroutineDeclaration{
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.SUBROUTINE,
						Literal:  "sub",
						Line:     28,
						Position: 1,
					},
					Nest:               0,
					PreviousEmptyLines: 1,
					Leading:            comments(),
					Infix:              comments(),
					Trailing:           comments(),
					EndLine:            28,
					EndPosition:        16,
				},
				Name: &ast.Ident{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.IDENT,
							Literal:  "test_recv",
							Line:     28,
							Position: 5,
						},
						Nest:               0,
						PreviousEmptyLines: 0,
						Leading:            comments(),
						Infix:              comments(),
						Trailing:           comments(),
						EndLine:            28,
						EndPosition:        13,
					},
					Value: "test_recv",
				},
				Block: &ast.BlockStatement{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.LEFT_BRACE,
							Literal:  "{",
							Line:     28,
							Position: 15,
						},
						Nest:               1,
						PreviousEmptyLines: 0,
						Leading:            comments(),
						Infix:              comments(),
						Trailing:           comments(),
						EndLine:            28,
						EndPosition:        16,
					},
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
