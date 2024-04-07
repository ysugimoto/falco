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
		cmpopts.IgnoreFields(ast.Comment{}, "Token", "PrefixedLineFeed"),
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
								Value: "req.http.v1",
							},
							Operator: &ast.Operator{
								Meta:     ast.New(T, 1),
								Operator: "=",
							},
							Value: &ast.String{
								Meta:  ast.New(T, 1),
								Value: "foo bar",
							},
						},
						&ast.SetStatement{
							Meta: ast.New(T, 1),
							Ident: &ast.Ident{
								Meta:  ast.New(T, 1),
								Value: "req.http.v2",
							},
							Operator: &ast.Operator{
								Meta:     ast.New(T, 1),
								Operator: "=",
							},
							Value: &ast.String{
								Meta:  ast.New(T, 1),
								Value: "foo%20bar",
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
				Meta: ast.New(T, 0, comments("// subroutine leading")),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0, comments("/* subroutine ident leading */")),
					Value: "vcl_recv",
				},
				Block: &ast.BlockStatement{
					Meta: ast.New(T, 1, comments("/* subroutine block leading */"), comments("// subroutine trailing"), comments("// subroutine block infix")),
					Statements: []ast.Statement{
						&ast.IfStatement{
							Meta: ast.New(T, 1, comments("// if leading")),
							Condition: &ast.InfixExpression{
								Meta: ast.New(T, 1),
								Left: &ast.Ident{
									Meta:  ast.New(T, 1),
									Value: "req.http.Host",
								},
								Operator: "&&",
								Right: &ast.InfixExpression{
									Meta: ast.New(T, 1),
									Left: &ast.Ident{
										Meta:  ast.New(T, 1, comments("# req.http.Foo leading")),
										Value: "req.http.Foo",
									},
									Operator: "==",
									Right: &ast.String{
										Meta:  ast.New(T, 1),
										Value: "bar",
									},
								},
							},
							Consequence: &ast.BlockStatement{
								Meta: ast.New(T, 2, ast.Comments{}, comments("// if trailing"), comments("// if infix")),
								Statements: []ast.Statement{
									&ast.SetStatement{
										Meta: ast.New(T, 2, comments("// set leading")),
										Ident: &ast.Ident{
											Meta:  ast.New(T, 2),
											Value: "req.http.Host",
										},
										Operator: &ast.Operator{
											Meta:     ast.New(T, 2),
											Operator: "=",
										},
										Value: &ast.String{
											Meta:  ast.New(T, 2, comments("/* expression leading */"), comments("/* expression trailing */")),
											Value: "bar",
										},
									},
									&ast.SetStatement{
										Meta: ast.New(T, 2),
										Ident: &ast.Ident{
											Meta:  ast.New(T, 2),
											Value: "req.http.Host",
										},
										Operator: &ast.Operator{
											Meta:     ast.New(T, 2),
											Operator: "=",
										},
										Value: &ast.InfixExpression{
											Meta: ast.New(T, 2, ast.Comments{}, comments("/* expression trailing */")),
											Left: &ast.String{
												Meta:  ast.New(T, 2, comments("/* expression leading */"), comments("/* infix expression leading */")),
												Value: "bar",
											},
											Operator: "+",
											Right: &ast.String{
												Meta:  ast.New(T, 2, ast.Comments{}, comments("/* expression trailing */")),
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

func TestNewCommentModel(t *testing.T) {
	input := `
/* 1 */ sub /* 2 */ foo /* 3 */ {
  /* 4 */ 
  /* 5 */ declare /* 6 */ local /* 7 */ var.s /* 8 */ STRING /* 9 */; /* 10 */
  /* 11 */
} /* 12 */
/* 13 */
`
	decl := &ast.DeclareStatement{
		Meta: ast.New(T, 1, comments("/* 4 */", "/* 5 */"), comments("/* 10 */", "/* 11 */"), comments("/* 6 */")),
		Name: &ast.Ident{
			Meta:  ast.New(T, 1, comments("/* 7 */"), comments("/* 8 */")),
			Value: "var.s",
		},
		ValueType: &ast.Ident{
			Meta:  ast.New(T, 1, comments(), comments("/* 9 */")),
			Value: "STRING",
		},
	}
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.SubroutineDeclaration{
				Meta: ast.New(T, 0, comments("/* 1 */"), comments("/* 12 */", "/* 13 */")),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0, comments("/* 2 */"), comments("/* 3 */")),
					Value: "foo",
				},
				Block: &ast.BlockStatement{
					Meta:       ast.New(T, 1),
					Statements: []ast.Statement{decl},
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
