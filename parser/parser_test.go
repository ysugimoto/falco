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

func assert(t *testing.T, actual, expect any) {

	if diff := cmp.Diff(expect, actual,
		// Meta structs ignores Token info
		cmpopts.IgnoreFields(ast.Comment{}, "Token", "PrefixedLineFeed"),
		cmpopts.IgnoreFields(ast.Meta{}, "ID"),
		cmpopts.IgnoreFields(token.Token{}, "Offset"),
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
		cmpopts.IgnoreFields(ast.IfStatement{}),
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
	set var.S = "foo" "bar" + "baz" {"long"} {delimited"long"delimited};
}`
	_, err := New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Error(err)
	}
}

func TestLongStringDelimiterMismatch(t *testing.T) {
	input := `// Subroutine
sub vcl_recv {
	declare local var.S STRING;
	set var.S = {delimited"long"mismatch};
}`
	_, err := New(lexer.NewFromString(input)).ParseVCL()
	if err == nil {
		t.Errorf("expects error but got nil")
	}
}

func TestStringLiteralEscapes(t *testing.T) {
	// % escapes are only expanded in double-quote strings.
	input := `
sub vcl_recv {
	set req.http.v1 = "foo%20bar";
	set req.http.v2 = {"foo%20bar"};
}`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.SubroutineDeclaration{
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.SUBROUTINE,
						Literal:  "sub",
						Line:     2,
						Position: 1,
					},
					Leading:            comments(),
					Trailing:           comments(),
					Infix:              comments(),
					Nest:               0,
					PreviousEmptyLines: 0,
					EndLine:            5,
					EndPosition:        1,
				},
				Name: &ast.Ident{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.IDENT,
							Literal:  "vcl_recv",
							Line:     2,
							Position: 5,
						},
						Leading:            comments(),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            2,
						EndPosition:        12,
					},
					Value: "vcl_recv",
				},
				Block: &ast.BlockStatement{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.LEFT_BRACE,
							Literal:  "{",
							Line:     2,
							Position: 14,
						},
						Leading:            comments(),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               1,
						PreviousEmptyLines: 0,
						EndLine:            5,
						EndPosition:        1,
					},
					Statements: []ast.Statement{
						&ast.SetStatement{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.SET,
									Literal:  "set",
									Line:     3,
									Position: 2,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            3,
								EndPosition:        28,
							},
							Ident: &ast.Ident{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.IDENT,
										Literal:  "req.http.v1",
										Line:     3,
										Position: 6,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            3,
									EndPosition:        16,
								},
								Value: "req.http.v1",
							},
							Operator: &ast.Operator{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.ASSIGN,
										Literal:  "=",
										Line:     3,
										Position: 18,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            3,
									EndPosition:        18,
								},
								Operator: "=",
							},
							Value: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "foo%20bar",
										Line:     3,
										Position: 20,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            3,
									EndPosition:        28,
								},
								Value: "foo bar",
							},
						},
						&ast.SetStatement{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.SET,
									Literal:  "set",
									Line:     4,
									Position: 2,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            4,
								EndPosition:        32,
							},
							Ident: &ast.Ident{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.IDENT,
										Literal:  "req.http.v2",
										Line:     4,
										Position: 6,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            4,
									EndPosition:        16,
								},
								Value: "req.http.v2",
							},
							Operator: &ast.Operator{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.ASSIGN,
										Literal:  "=",
										Line:     4,
										Position: 18,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            4,
									EndPosition:        18,
								},
								Operator: "=",
							},
							Value: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "foo%20bar",
										Line:     4,
										Position: 20,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            4,
									EndPosition:        32,
								},
								Value:      "foo%20bar",
								LongString: true,
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
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.SUBROUTINE,
						Literal:  "sub",
						Line:     2,
						Position: 1,
					},
					Leading:            comments(),
					Trailing:           comments(),
					Infix:              comments(),
					Nest:               0,
					PreviousEmptyLines: 0,
					EndLine:            4,
					EndPosition:        1,
				},
				Name: &ast.Ident{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.IDENT,
							Literal:  "vcl_recv",
							Line:     2,
							Position: 5,
						},
						Leading:            comments(),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            2,
						EndPosition:        12,
					},
					Value: "vcl_recv",
				},
				Block: &ast.BlockStatement{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.LEFT_BRACE,
							Literal:  "{",
							Line:     2,
							Position: 14,
						},
						Leading:            comments(),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               1,
						PreviousEmptyLines: 0,
						EndLine:            4,
						EndPosition:        1,
					},
					Statements: []ast.Statement{
						&ast.SetStatement{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.SET,
									Literal:  "set",
									Line:     3,
									Position: 2,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            3,
								EndPosition:        38,
							},
							Ident: &ast.Ident{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.IDENT,
										Literal:  "var.Bool",
										Line:     3,
										Position: 6,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            3,
									EndPosition:        13,
								},
								Value: "var.Bool",
							},
							Operator: &ast.Operator{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.ASSIGN,
										Literal:  "=",
										Line:     3,
										Position: 15,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            3,
									EndPosition:        15,
								},
								Operator: "=",
							},
							Value: &ast.GroupedExpression{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.LEFT_PAREN,
										Literal:  "(",
										Line:     3,
										Position: 17,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            3,
									EndPosition:        38,
								},
								Right: &ast.InfixExpression{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "var.IsOk",
											Line:     3,
											Position: 18,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            3,
										EndPosition:        37,
									},
									Left: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "var.IsOk",
												Line:     3,
												Position: 18,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            3,
											EndPosition:        25,
										},
										Value: "var.IsOk",
									},
									Operator: "&&",
									Right: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "var.IsNg",
												Line:     3,
												Position: 30,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            3,
											EndPosition:        37,
										},
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
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.SUBROUTINE,
						Literal:  "sub",
						Line:     2,
						Position: 1,
					},
					Leading:            comments(),
					Trailing:           comments(),
					Infix:              comments(),
					Nest:               0,
					PreviousEmptyLines: 0,
					EndLine:            4,
					EndPosition:        1,
				},
				Name: &ast.Ident{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.IDENT,
							Literal:  "vcl_recv",
							Line:     2,
							Position: 5,
						},
						Leading:            comments(),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            2,
						EndPosition:        12,
					},
					Value: "vcl_recv",
				},
				Block: &ast.BlockStatement{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.LEFT_BRACE,
							Literal:  "{",
							Line:     2,
							Position: 14,
						},
						Leading:            comments(),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               1,
						PreviousEmptyLines: 0,
						EndLine:            4,
						EndPosition:        1,
					},
					Statements: []ast.Statement{
						&ast.ErrorStatement{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.ERROR,
									Literal:  "error",
									Line:     3,
									Position: 2,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            3,
								EndPosition:        6,
							},
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

func TestAllCommentPositions(t *testing.T) {
	input := `
// subroutine leading
sub /* subroutine ident leading */ vcl_recv /* subroutine block leading */ {
	// if leading
	if (
		req.http.Host &&
		# req.http.Foo leading
		req.http.Foo == "bar"
	) {
		// set leading
		set req.http.Host = /* expression leading */ "bar" /* expression trailing */;
		set req.http.Host = /* expression leading */ "bar" /* infix expression leading */ "baz" /* expression trailing */;
		// if infix
	} // if trailing
	// subroutine block infix
} // subroutine trailing`

	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.SubroutineDeclaration{
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.SUBROUTINE,
						Literal:  "sub",
						Line:     3,
						Position: 1,
					},
					Leading:            comments("// subroutine leading"),
					Trailing:           comments(),
					Infix:              comments(),
					Nest:               0,
					PreviousEmptyLines: 0,
					EndLine:            16,
					EndPosition:        1,
				},
				Name: &ast.Ident{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.IDENT,
							Literal:  "vcl_recv",
							Line:     3,
							Position: 36,
						},
						Leading:            comments("/* subroutine ident leading */"),
						Trailing:           comments("/* subroutine block leading */"),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            3,
						EndPosition:        43,
					},
					Value: "vcl_recv",
				},
				Block: &ast.BlockStatement{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.LEFT_BRACE,
							Literal:  "{",
							Line:     3,
							Position: 76,
						},
						Leading:            comments(),
						Trailing:           comments("// subroutine trailing"),
						Infix:              comments("// subroutine block infix"),
						Nest:               1,
						PreviousEmptyLines: 0,
						EndLine:            16,
						EndPosition:        1,
					},
					Statements: []ast.Statement{
						&ast.IfStatement{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.IF,
									Literal:  "if",
									Line:     5,
									Position: 2,
								},
								Leading:            comments("// if leading"),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            14,
								EndPosition:        2,
							},
							Keyword: "if",
							Condition: &ast.InfixExpression{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.IDENT,
										Literal:  "req.http.Host",
										Line:     6,
										Position: 3,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            8,
									EndPosition:        23,
								},
								Left: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.Host",
											Line:     6,
											Position: 3,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            6,
										EndPosition:        15,
									},
									Value: "req.http.Host",
								},
								Operator: "&&",
								Right: &ast.InfixExpression{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.Foo",
											Line:     8,
											Position: 3,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            8,
										EndPosition:        23,
									},
									Left: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.Foo",
												Line:     8,
												Position: 3,
											},
											Leading:            comments("# req.http.Foo leading"),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            8,
											EndPosition:        14,
										},
										Value: "req.http.Foo",
									},
									Operator: "==",
									Right: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "bar",
												Line:     8,
												Position: 19,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            8,
											EndPosition:        23,
										},
										Value: "bar",
									},
								},
							},
							Consequence: &ast.BlockStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.LEFT_BRACE,
										Literal:  "{",
										Line:     9,
										Position: 4,
									},
									Leading:            comments(),
									Trailing:           comments("// if trailing"),
									Infix:              comments("// if infix"),
									Nest:               2,
									PreviousEmptyLines: 0,
									EndLine:            14,
									EndPosition:        2,
								},
								Statements: []ast.Statement{
									&ast.SetStatement{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.SET,
												Literal:  "set",
												Line:     11,
												Position: 3,
											},
											Leading:            comments("// set leading"),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            11,
											EndPosition:        52,
										},
										Ident: &ast.Ident{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.IDENT,
													Literal:  "req.http.Host",
													Line:     11,
													Position: 7,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            11,
												EndPosition:        19,
											},
											Value: "req.http.Host",
										},
										Operator: &ast.Operator{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.ASSIGN,
													Literal:  "=",
													Line:     11,
													Position: 21,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            11,
												EndPosition:        21,
											},
											Operator: "=",
										},
										Value: &ast.String{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.STRING,
													Literal:  "bar",
													Line:     11,
													Position: 48,
												},
												Leading:            comments("/* expression leading */"),
												Trailing:           comments("/* expression trailing */"),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            11,
												EndPosition:        52,
											},
											Value: "bar",
										},
									},
									&ast.SetStatement{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.SET,
												Literal:  "set",
												Line:     12,
												Position: 3,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            12,
											EndPosition:        89,
										},
										Ident: &ast.Ident{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.IDENT,
													Literal:  "req.http.Host",
													Line:     12,
													Position: 7,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            12,
												EndPosition:        19,
											},
											Value: "req.http.Host",
										},
										Operator: &ast.Operator{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.ASSIGN,
													Literal:  "=",
													Line:     12,
													Position: 21,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            12,
												EndPosition:        21,
											},
											Operator: "=",
										},
										Value: &ast.InfixExpression{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.STRING,
													Literal:  "bar",
													Line:     12,
													Position: 48,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            12,
												EndPosition:        89,
											},
											Left: &ast.String{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.STRING,
														Literal:  "bar",
														Line:     12,
														Position: 48,
													},
													Leading:            comments("/* expression leading */"),
													Trailing:           comments("/* infix expression leading */"),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            12,
													EndPosition:        52,
												},
												Value: "bar",
											},
											Operator: "+",
											Right: &ast.String{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.STRING,
														Literal:  "baz",
														Line:     12,
														Position: 85,
													},
													Leading:            comments(),
													Trailing:           comments("/* expression trailing */"),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            12,
													EndPosition:        89,
												},
												Value: "baz",
											},
										},
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

func TestCountPreviousEmptyLines(t *testing.T) {
	input := `
sub vcl_recv {


	set req.http.Foo = "bar";
}`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.SubroutineDeclaration{
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.SUBROUTINE,
						Literal:  "sub",
						Line:     2,
						Position: 1,
					},
					Leading:            comments(),
					Trailing:           comments(),
					Infix:              comments(),
					Nest:               0,
					PreviousEmptyLines: 0,
					EndLine:            6,
					EndPosition:        1,
				},
				Name: &ast.Ident{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.IDENT,
							Literal:  "vcl_recv",
							Line:     2,
							Position: 5,
						},
						Leading:            comments(),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            2,
						EndPosition:        12,
					},
					Value: "vcl_recv",
				},
				Block: &ast.BlockStatement{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.LEFT_BRACE,
							Literal:  "{",
							Line:     2,
							Position: 14,
						},
						Leading:            comments(),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               1,
						PreviousEmptyLines: 0,
						EndLine:            6,
						EndPosition:        1,
					},
					Statements: []ast.Statement{
						&ast.SetStatement{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.SET,
									Literal:  "set",
									Line:     5,
									Position: 2,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 2,
								EndLine:            5,
								EndPosition:        25,
							},
							Ident: &ast.Ident{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.IDENT,
										Literal:  "req.http.Foo",
										Line:     5,
										Position: 6,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            5,
									EndPosition:        17,
								},
								Value: "req.http.Foo",
							},
							Operator: &ast.Operator{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.ASSIGN,
										Literal:  "=",
										Line:     5,
										Position: 19,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            5,
									EndPosition:        19,
								},
								Operator: "=",
							},
							Value: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "bar",
										Line:     5,
										Position: 21,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            5,
									EndPosition:        25,
								},
								Value: "bar",
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

func TestSkipFastlyControlSyntaxes(t *testing.T) {
	input := `
pragma optional_param geoip_opt_in true;
pragma optional_param max_object_size 2147483648;
pragma optional_param smiss_max_object_size 5368709120;
pragma optional_param fetchless_purge_all 1;
pragma optional_param chash_randomize_on_pass true;
pragma optional_param default_ssl_check_cert 1;
pragma optional_param max_backends 20;
pragma optional_param customer_id "bwIxaoVzhiEJrt4SIaIvT";
C!
W!
# Backends

backend F_Host_1 {
	.host = "example.com";
}
`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.BackendDeclaration{
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.BACKEND,
						Literal:  "backend",
						Line:     14,
						Position: 1,
					},
					Leading:            comments("# Backends"),
					Trailing:           comments(),
					Infix:              comments(),
					Nest:               0,
					PreviousEmptyLines: 1,
					EndLine:            16,
					EndPosition:        1,
				},
				Name: &ast.Ident{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.IDENT,
							Literal:  "F_Host_1",
							Line:     14,
							Position: 9,
						},
						Leading:            comments(),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            14,
						EndPosition:        16,
					},
					Value: "F_Host_1",
				},
				Properties: []*ast.BackendProperty{
					{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.DOT,
								Literal:  ".",
								Line:     15,
								Position: 2,
							},
							Leading:            comments(),
							Trailing:           comments(),
							Infix:              comments(),
							Nest:               1,
							PreviousEmptyLines: 0,
							EndLine:            15,
							EndPosition:        22,
						},
						Key: &ast.Ident{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.IDENT,
									Literal:  "host",
									Line:     15,
									Position: 3,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            15,
								EndPosition:        6,
							},
							Value: "host",
						},
						Value: &ast.String{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "example.com",
									Line:     15,
									Position: 10,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            15,
								EndPosition:        22,
							},
							Value: "example.com",
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
