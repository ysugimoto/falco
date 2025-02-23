package parser

import (
	"fmt"
	"testing"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/token"
)

func TestParseImport(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect any
	}{
		{
			name: "basic parse",
			input: `
// Leading comment
import boltsort; // Trailing comment
`,
			expect: &ast.VCL{
				Statements: []ast.Statement{
					&ast.ImportStatement{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.IMPORT,
								Literal:  "import",
								Line:     3,
								Position: 1,
							},
							Leading:            comments("// Leading comment"),
							Trailing:           comments("// Trailing comment"),
							Infix:              comments(),
							Nest:               0,
							PreviousEmptyLines: 0,
							EndLine:            3,
							EndPosition:        15,
						},
						Name: &ast.Ident{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.IDENT,
									Literal:  "boltsort",
									Line:     3,
									Position: 8,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               0,
								PreviousEmptyLines: 0,
								EndLine:            3,
								EndPosition:        15,
							},
							Value: "boltsort",
						},
					},
				},
			},
		},
		{
			name: "complex comments",
			input: `
// a
import /* b */boltsort /* c */; // d
`,
			expect: &ast.VCL{
				Statements: []ast.Statement{
					&ast.ImportStatement{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.IMPORT,
								Literal:  "import",
								Line:     3,
								Position: 1,
							},
							Leading:            comments("// a"),
							Trailing:           comments("// d"),
							Infix:              comments(),
							Nest:               0,
							PreviousEmptyLines: 0,
							EndLine:            3,
							EndPosition:        22,
						},
						Name: &ast.Ident{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.IDENT,
									Literal:  "boltsort",
									Line:     3,
									Position: 15,
								},
								Leading:            comments("/* b */"),
								Trailing:           comments("/* c */"),
								Infix:              comments(),
								Nest:               0,
								PreviousEmptyLines: 0,
								EndLine:            3,
								EndPosition:        22,
							},
							Value: "boltsort",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vcl, err := New(lexer.NewFromString(tt.input)).ParseVCL()
			if err != nil {
				t.Errorf("%+v", err)
			}
			assert(t, vcl, tt.expect)
		})
	}
}

func TestParseInclude(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect any
	}{
		{
			name: "with semicolon at the end",
			input: `
// Leading comment
include "feature_mod"; // Trailing comment
`,
			expect: &ast.VCL{
				Statements: []ast.Statement{
					&ast.IncludeStatement{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.INCLUDE,
								Literal:  "include",
								Line:     3,
								Position: 1,
							},
							Leading:            comments("// Leading comment"),
							Trailing:           comments("// Trailing comment"),
							Infix:              comments(),
							Nest:               0,
							PreviousEmptyLines: 0,
							EndLine:            3,
							EndPosition:        21,
						},
						Module: &ast.String{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "feature_mod",
									Line:     3,
									Position: 9,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               0,
								PreviousEmptyLines: 0,
								EndLine:            3,
								EndPosition:        21,
							},
							Value: "feature_mod",
						},
					},
				},
			},
		},
		{
			name: "without semicolon at the end",
			input: `
// Leading comment
include "feature_mod" // Trailing comment
`,
			expect: &ast.VCL{
				Statements: []ast.Statement{
					&ast.IncludeStatement{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.INCLUDE,
								Literal:  "include",
								Line:     3,
								Position: 1,
							},
							Leading:            comments("// Leading comment"),
							Trailing:           comments("// Trailing comment"),
							Infix:              comments(),
							Nest:               0,
							PreviousEmptyLines: 0,
							EndLine:            3,
							EndPosition:        21,
						},
						Module: &ast.String{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "feature_mod",
									Line:     3,
									Position: 9,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               0,
								PreviousEmptyLines: 0,
								EndLine:            3,
								EndPosition:        21,
							},
							Value: "feature_mod",
						},
					},
				},
			},
		},
		{
			name: "complex comments with semicolon at the end",
			input: `
// a
include /* b */"feature_mod"/* c */; // d
`,
			expect: &ast.VCL{
				Statements: []ast.Statement{
					&ast.IncludeStatement{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.INCLUDE,
								Literal:  "include",
								Line:     3,
								Position: 1,
							},
							Leading:            comments("// a"),
							Trailing:           comments("// d"),
							Infix:              comments(),
							Nest:               0,
							PreviousEmptyLines: 0,
							EndLine:            3,
							EndPosition:        28,
						},
						Module: &ast.String{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "feature_mod",
									Line:     3,
									Position: 16,
								},
								Leading:            comments("/* b */"),
								Trailing:           comments("/* c */"),
								Infix:              comments(),
								Nest:               0,
								PreviousEmptyLines: 0,
								EndLine:            3,
								EndPosition:        28,
							},
							Value: "feature_mod",
						},
					},
				},
			},
		},
		{
			name: "complex comments without semicolon at the end",
			input: `
// a
include /* b */"feature_mod"/* c */ // d
`,
			expect: &ast.VCL{
				Statements: []ast.Statement{
					&ast.IncludeStatement{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.INCLUDE,
								Literal:  "include",
								Line:     3,
								Position: 1,
							},
							Leading:            comments("// a"),
							Trailing:           comments("/* c */", "// d"),
							Infix:              comments(),
							Nest:               0,
							PreviousEmptyLines: 0,
							EndLine:            3,
							EndPosition:        28,
						},
						Module: &ast.String{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "feature_mod",
									Line:     3,
									Position: 16,
								},
								Leading:            comments("/* b */"),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               0,
								PreviousEmptyLines: 0,
								EndLine:            3,
								EndPosition:        28,
							},
							Value: "feature_mod",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vcl, err := New(lexer.NewFromString(tt.input)).ParseVCL()
			if err != nil {
				t.Errorf("%+v", err)
			}
			assert(t, vcl, tt.expect)
		})
	}
}

func TestParseSetStatement(t *testing.T) {
	t.Run("simple assign", func(t *testing.T) {
		operators := map[string]token.TokenType{
			// simple assign
			"=": token.ASSIGN,

			// arithmetic operator
			"+=": token.ADDITION,
			"-=": token.SUBTRACTION,
			"*=": token.MULTIPLICATION,
			"/=": token.DIVISION,

			// bitwise operator
			"%=": token.REMAINDER,
			"|=": token.BITWISE_OR,
			"&=": token.BITWISE_AND,
			"^=": token.BITWISE_XOR,

			// bit shifts operator
			"<<=":  token.LEFT_SHIFT,
			">>=":  token.RIGHT_SHIFT,
			"rol=": token.LEFT_ROTATE,
			"ror=": token.RIGHT_ROTATE,

			// logical operator
			"||=": token.LOGICAL_OR,
			"&&=": token.LOGICAL_AND,
		}

		for op, tt := range operators {
			input := fmt.Sprintf(`
// Subroutine
sub vcl_recv {
	// Leading comment
	set /* Host */ req.http.Host %s "example.com"; // Trailing comment
}
`,
				op)
			size := len(op)
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
							Leading:            comments("// Subroutine"),
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
									Line:     3,
									Position: 5,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               0,
								PreviousEmptyLines: 0,
								EndLine:            3,
								EndPosition:        12,
							},
							Value: "vcl_recv",
						},
						Block: &ast.BlockStatement{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.LEFT_BRACE,
									Literal:  "{",
									Line:     3,
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
										Leading:            comments("// Leading comment"),
										Trailing:           comments("// Trailing comment"),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            5,
										EndPosition:        44 + size,
									},
									Ident: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.Host",
												Line:     5,
												Position: 17,
											},
											Leading:            comments("/* Host */"),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            5,
											EndPosition:        29,
										},
										Value: "req.http.Host",
									},
									Operator: &ast.Operator{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     tt,
												Literal:  op,
												Line:     5,
												Position: 31,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            5,
											EndPosition:        31 + size - 1,
										},
										Operator: op,
									},
									Value: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "example.com",
												Line:     5,
												Position: 31 + size - 1 + 2,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            5,
											EndPosition:        31 + size - 1 + 2 + 12,
										},
										Value: "example.com",
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
	})

	t.Run("with string concatenation", func(t *testing.T) {
		input := `
// Subroutine
sub vcl_recv {
	// Leading comment
	set /* Host */ req.http.Host = "example." req.http.User-Agent ".com"; // Trailing comment
}
`
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
						Leading:            comments("// Subroutine"),
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
								Line:     3,
								Position: 5,
							},
							Leading:            comments(),
							Trailing:           comments(),
							Infix:              comments(),
							Nest:               0,
							PreviousEmptyLines: 0,
							EndLine:            3,
							EndPosition:        12,
						},
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.LEFT_BRACE,
								Literal:  "{",
								Line:     3,
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
									Leading:            comments("// Leading comment"),
									Trailing:           comments("// Trailing comment"),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            5,
									EndPosition:        69,
								},
								Ident: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.Host",
											Line:     5,
											Position: 17,
										},
										Leading:            comments("/* Host */"),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            5,
										EndPosition:        29,
									},
									Value: "req.http.Host",
								},
								Operator: &ast.Operator{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.ASSIGN,
											Literal:  "=",
											Line:     5,
											Position: 31,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            5,
										EndPosition:        31,
									},
									Operator: "=",
								},
								Value: &ast.InfixExpression{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.STRING,
											Literal:  "example.",
											Line:     5,
											Position: 33,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            5,
										EndPosition:        69,
									},
									Operator: "+",
									Left: &ast.InfixExpression{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "example.",
												Line:     5,
												Position: 33,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            5,
											EndPosition:        62,
										},
										Operator: "+",
										Left: &ast.String{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.STRING,
													Literal:  "example.",
													Line:     5,
													Position: 33,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            5,
												EndPosition:        42,
											},
											Value: "example.",
										},
										Right: &ast.Ident{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.IDENT,
													Literal:  "req.http.User-Agent",
													Line:     5,
													Position: 44,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            5,
												EndPosition:        62,
											},
											Value: "req.http.User-Agent",
										},
									},
									Right: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  ".com",
												Line:     5,
												Position: 64,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            5,
											EndPosition:        69,
										},
										Value: ".com",
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
	})

	t.Run("complex comments", func(t *testing.T) {
		input := `
sub vcl_recv {
	// a
	set /* a */ req.http.Host /* b */= /* c */"example." /* d */req.http.User-Agent /* e */; // f
}
`
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
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// a"),
									Trailing:           comments("// f"),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            4,
									EndPosition:        80,
								},
								Ident: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.Host",
											Line:     4,
											Position: 14,
										},
										Leading:            comments("/* a */"),
										Trailing:           comments("/* b */"),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        26,
									},
									Value: "req.http.Host",
								},
								Operator: &ast.Operator{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.ASSIGN,
											Literal:  "=",
											Line:     4,
											Position: 35,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        35,
									},
									Operator: "=",
								},
								Value: &ast.InfixExpression{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.STRING,
											Literal:  "example.",
											Line:     4,
											Position: 44,
										},
										Leading:            comments("/* c */"),
										Trailing:           comments("/* d */"),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        80,
									},
									Operator: "+",
									Left: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "example.",
												Line:     4,
												Position: 44,
											},
											Leading:            comments("/* c */"),
											Trailing:           comments("/* d */"),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        53,
										},
										Value: "example.",
									},
									Right: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.User-Agent",
												Line:     4,
												Position: 62,
											},
											Leading:            comments(),
											Trailing:           comments("/* e */"),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        80,
										},
										Value: "req.http.User-Agent",
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
	})
}

func TestParseIfStatement(t *testing.T) {
	t.Run("only if", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	if (req.http.Host ~ /* infix */"example.com") {
		restart;
	} // Trailing comment
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
						Leading:            comments("// Subroutine"),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            7,
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
							EndLine:            7,
							EndPosition:        1,
						},
						Statements: []ast.Statement{
							&ast.IfStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.IF,
										Literal:  "if",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// Leading comment"),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            6,
									EndPosition:        2,
								},
								Keyword: "if",
								Condition: &ast.InfixExpression{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.Host",
											Line:     4,
											Position: 6,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        45,
									},
									Operator: "~",
									Left: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.Host",
												Line:     4,
												Position: 6,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        18,
										},
										Value: "req.http.Host",
									},
									Right: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "example.com",
												Line:     4,
												Position: 33,
											},
											Leading:            comments("/* infix */"),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        45,
										},
										Value: "example.com",
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.LEFT_BRACE,
											Literal:  "{",
											Line:     4,
											Position: 48,
										},
										Leading:            comments(),
										Trailing:           comments("// Trailing comment"),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            6,
										EndPosition:        2,
									},
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.RESTART,
													Literal:  "restart",
													Line:     5,
													Position: 3,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            5,
												EndPosition:        9,
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
	})

	t.Run("logical and condtions", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	if (req.http.Host ~ "example.com" && /* infix */req.http.Host == "foobar") {
		restart;
	} // Trailing comment
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
						Leading:            comments("// Subroutine"),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            7,
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
							EndLine:            7,
							EndPosition:        1,
						},
						Statements: []ast.Statement{
							&ast.IfStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.IF,
										Literal:  "if",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// Leading comment"),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            6,
									EndPosition:        2,
								},
								Keyword: "if",
								Condition: &ast.InfixExpression{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.Host",
											Line:     4,
											Position: 6,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        74,
									},
									Operator: "&&",
									Left: &ast.InfixExpression{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.Host",
												Line:     4,
												Position: 6,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        34,
										},
										Operator: "~",
										Left: &ast.Ident{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.IDENT,
													Literal:  "req.http.Host",
													Line:     4,
													Position: 6,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            4,
												EndPosition:        18,
											},
											Value: "req.http.Host",
										},
										Right: &ast.String{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.STRING,
													Literal:  "example.com",
													Line:     4,
													Position: 22,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            4,
												EndPosition:        34,
											},
											Value: "example.com",
										},
									},
									Right: &ast.InfixExpression{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.Host",
												Line:     4,
												Position: 50,
											},
											Leading:            comments("/* infix */"),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        74,
										},
										Operator: "==",
										Left: &ast.Ident{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.IDENT,
													Literal:  "req.http.Host",
													Line:     4,
													Position: 50,
												},
												Leading:            comments("/* infix */"),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            4,
												EndPosition:        62,
											},
											Value: "req.http.Host",
										},
										Right: &ast.String{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.STRING,
													Literal:  "foobar",
													Line:     4,
													Position: 67,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            4,
												EndPosition:        74,
											},
											Value: "foobar",
										},
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.LEFT_BRACE,
											Literal:  "{",
											Line:     4,
											Position: 77,
										},
										Leading:            comments(),
										Trailing:           comments("// Trailing comment"),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            6,
										EndPosition:        2,
									},
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.RESTART,
													Literal:  "restart",
													Line:     5,
													Position: 3,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            5,
												EndPosition:        9,
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
	})

	t.Run("logical or condtions", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	if (req.http.Host ~ "example.com" || req.http.Host == "foobar") {
		restart;
	}
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
						Leading:            comments("// Subroutine"),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            7,
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
							EndLine:            7,
							EndPosition:        1,
						},
						Statements: []ast.Statement{
							&ast.IfStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.IF,
										Literal:  "if",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// Leading comment"),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            6,
									EndPosition:        2,
								},
								Keyword: "if",
								Condition: &ast.InfixExpression{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.Host",
											Line:     4,
											Position: 6,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        63,
									},
									Operator: "||",
									Left: &ast.InfixExpression{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.Host",
												Line:     4,
												Position: 6,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        34,
										},
										Operator: "~",
										Left: &ast.Ident{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.IDENT,
													Literal:  "req.http.Host",
													Line:     4,
													Position: 6,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            4,
												EndPosition:        18,
											},
											Value: "req.http.Host",
										},
										Right: &ast.String{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.STRING,
													Literal:  "example.com",
													Line:     4,
													Position: 22,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            4,
												EndPosition:        34,
											},
											Value: "example.com",
										},
									},
									Right: &ast.InfixExpression{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.Host",
												Line:     4,
												Position: 39,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        63,
										},
										Operator: "==",
										Left: &ast.Ident{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.IDENT,
													Literal:  "req.http.Host",
													Line:     4,
													Position: 39,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            4,
												EndPosition:        51,
											},
											Value: "req.http.Host",
										},
										Right: &ast.String{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.STRING,
													Literal:  "foobar",
													Line:     4,
													Position: 56,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            4,
												EndPosition:        63,
											},
											Value: "foobar",
										},
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.LEFT_BRACE,
											Literal:  "{",
											Line:     4,
											Position: 66,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            6,
										EndPosition:        2,
									},
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.RESTART,
													Literal:  "restart",
													Line:     5,
													Position: 3,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            5,
												EndPosition:        9,
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
	})

	t.Run("combination of boolean conditions", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	if (true || false && false) {
		restart;
	}
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
						Leading:            comments("// Subroutine"),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            7,
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
							EndLine:            7,
							EndPosition:        1,
						},
						Statements: []ast.Statement{
							&ast.IfStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.IF,
										Literal:  "if",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// Leading comment"),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            6,
									EndPosition:        2,
								},
								Keyword: "if",
								Condition: &ast.InfixExpression{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.TRUE,
											Literal:  "true",
											Line:     4,
											Position: 6,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        27,
									},
									Operator: "||",
									Left: &ast.Boolean{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.TRUE,
												Literal:  "true",
												Line:     4,
												Position: 6,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        9,
										},
										Value: true,
									},
									Right: &ast.InfixExpression{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.FALSE,
												Literal:  "false",
												Line:     4,
												Position: 14,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        27,
										},
										Operator: "&&",
										Left: &ast.Boolean{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.FALSE,
													Literal:  "false",
													Line:     4,
													Position: 14,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            4,
												EndPosition:        18,
											},
											Value: false,
										},
										Right: &ast.Boolean{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.FALSE,
													Literal:  "false",
													Line:     4,
													Position: 23,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            4,
												EndPosition:        27,
											},
											Value: false,
										},
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.LEFT_BRACE,
											Literal:  "{",
											Line:     4,
											Position: 30,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            6,
										EndPosition:        2,
									},
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.RESTART,
													Literal:  "restart",
													Line:     5,
													Position: 3,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            5,
												EndPosition:        9,
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
	})

	t.Run("if-else", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	if (req.http.Host ~ "example.com") {
		restart;
	}
	// Leading comment
	else {
		restart;
	} // Trailing comment
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
						Leading:            comments("// Subroutine"),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            11,
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
							EndLine:            11,
							EndPosition:        1,
						},
						Statements: []ast.Statement{
							&ast.IfStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.IF,
										Literal:  "if",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// Leading comment"),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            10,
									EndPosition:        2,
								},
								Keyword: "if",
								Condition: &ast.InfixExpression{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.Host",
											Line:     4,
											Position: 6,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        34,
									},
									Operator: "~",
									Left: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.Host",
												Line:     4,
												Position: 6,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        18,
										},
										Value: "req.http.Host",
									},
									Right: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "example.com",
												Line:     4,
												Position: 22,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        34,
										},
										Value: "example.com",
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.LEFT_BRACE,
											Literal:  "{",
											Line:     4,
											Position: 37,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            6,
										EndPosition:        2,
									},
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.RESTART,
													Literal:  "restart",
													Line:     5,
													Position: 3,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            5,
												EndPosition:        9,
											},
										},
									},
								},
								Alternative: &ast.ElseStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.ELSE,
											Literal:  "else",
											Line:     8,
											Position: 2,
										},
										Leading:            comments("// Leading comment"),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            10,
										EndPosition:        2,
									},
									Consequence: &ast.BlockStatement{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.LEFT_BRACE,
												Literal:  "{",
												Line:     8,
												Position: 7,
											},
											Leading:            comments(),
											Trailing:           comments("// Trailing comment"),
											Infix:              comments(),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            10,
											EndPosition:        2,
										},
										Statements: []ast.Statement{
											&ast.RestartStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.RESTART,
														Literal:  "restart",
														Line:     9,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            9,
													EndPosition:        9,
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
	})

	t.Run("if else if else", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	if (req.http.Host ~ "example.com") {
		restart;
	} else if (req.http.X-Forwarded-For ~ "192.168.0.1") {
		restart;
	} else {
		restart;
	}
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
						Leading:            comments("// Subroutine"),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            11,
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
							EndLine:            11,
							EndPosition:        1,
						},
						Statements: []ast.Statement{
							&ast.IfStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.IF,
										Literal:  "if",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// Leading comment"),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            10,
									EndPosition:        2,
								},
								Keyword: "if",
								Condition: &ast.InfixExpression{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.Host",
											Line:     4,
											Position: 6,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        34,
									},
									Operator: "~",
									Left: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.Host",
												Line:     4,
												Position: 6,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        18,
										},
										Value: "req.http.Host",
									},
									Right: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "example.com",
												Line:     4,
												Position: 22,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        34,
										},
										Value: "example.com",
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.LEFT_BRACE,
											Literal:  "{",
											Line:     4,
											Position: 37,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            6,
										EndPosition:        2,
									},
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.RESTART,
													Literal:  "restart",
													Line:     5,
													Position: 3,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            5,
												EndPosition:        9,
											},
										},
									},
								},
								Another: []*ast.IfStatement{
									{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IF,
												Literal:  "if",
												Line:     6,
												Position: 9,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            8,
											EndPosition:        2,
										},
										Keyword: "else if",
										Condition: &ast.InfixExpression{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.IDENT,
													Literal:  "req.http.X-Forwarded-For",
													Line:     6,
													Position: 13,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            6,
												EndPosition:        52,
											},
											Operator: "~",
											Left: &ast.Ident{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.IDENT,
														Literal:  "req.http.X-Forwarded-For",
														Line:     6,
														Position: 13,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               1,
													PreviousEmptyLines: 0,
													EndLine:            6,
													EndPosition:        36,
												},
												Value: "req.http.X-Forwarded-For",
											},
											Right: &ast.String{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.STRING,
														Literal:  "192.168.0.1",
														Line:     6,
														Position: 40,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               1,
													PreviousEmptyLines: 0,
													EndLine:            6,
													EndPosition:        52,
												},
												Value: "192.168.0.1",
											},
										},
										Consequence: &ast.BlockStatement{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.LEFT_BRACE,
													Literal:  "{",
													Line:     6,
													Position: 55,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            8,
												EndPosition:        2,
											},
											Statements: []ast.Statement{
												&ast.RestartStatement{
													Meta: &ast.Meta{
														Token: token.Token{
															Type:     token.RESTART,
															Literal:  "restart",
															Line:     7,
															Position: 3,
														},
														Leading:            comments(),
														Trailing:           comments(),
														Infix:              comments(),
														Nest:               2,
														PreviousEmptyLines: 0,
														EndLine:            7,
														EndPosition:        9,
													},
												},
											},
										},
									},
								},
								Alternative: &ast.ElseStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.ELSE,
											Literal:  "else",
											Line:     8,
											Position: 4,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            10,
										EndPosition:        2,
									},
									Consequence: &ast.BlockStatement{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.LEFT_BRACE,
												Literal:  "{",
												Line:     8,
												Position: 9,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            10,
											EndPosition:        2,
										},
										Statements: []ast.Statement{
											&ast.RestartStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.RESTART,
														Literal:  "restart",
														Line:     9,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            9,
													EndPosition:        9,
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
	})

	t.Run("if elseif else", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	if (req.http.Host ~ "example.com") {
		restart;
	} elseif (req.http.X-Forwarded-For ~ "192.168.0.1") {
		restart;
	} else {
		restart;
	}
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
						Leading:            comments("// Subroutine"),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            11,
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
							EndLine:            11,
							EndPosition:        1,
						},
						Statements: []ast.Statement{
							&ast.IfStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.IF,
										Literal:  "if",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// Leading comment"),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            10,
									EndPosition:        2,
								},
								Keyword: "if",
								Condition: &ast.InfixExpression{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.Host",
											Line:     4,
											Position: 6,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        34,
									},
									Operator: "~",
									Left: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.Host",
												Line:     4,
												Position: 6,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        18,
										},
										Value: "req.http.Host",
									},
									Right: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "example.com",
												Line:     4,
												Position: 22,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        34,
										},
										Value: "example.com",
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.LEFT_BRACE,
											Literal:  "{",
											Line:     4,
											Position: 37,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            6,
										EndPosition:        2,
									},
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.RESTART,
													Literal:  "restart",
													Line:     5,
													Position: 3,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            5,
												EndPosition:        9,
											},
										},
									},
								},
								Another: []*ast.IfStatement{
									{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.ELSEIF,
												Literal:  "elseif",
												Line:     6,
												Position: 4,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            8,
											EndPosition:        2,
										},
										Keyword: "elseif",
										Condition: &ast.InfixExpression{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.IDENT,
													Literal:  "req.http.X-Forwarded-For",
													Line:     6,
													Position: 12,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            6,
												EndPosition:        51,
											},
											Operator: "~",
											Left: &ast.Ident{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.IDENT,
														Literal:  "req.http.X-Forwarded-For",
														Line:     6,
														Position: 12,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               1,
													PreviousEmptyLines: 0,
													EndLine:            6,
													EndPosition:        35,
												},
												Value: "req.http.X-Forwarded-For",
											},
											Right: &ast.String{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.STRING,
														Literal:  "192.168.0.1",
														Line:     6,
														Position: 39,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               1,
													PreviousEmptyLines: 0,
													EndLine:            6,
													EndPosition:        51,
												},
												Value: "192.168.0.1",
											},
										},
										Consequence: &ast.BlockStatement{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.LEFT_BRACE,
													Literal:  "{",
													Line:     6,
													Position: 54,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            8,
												EndPosition:        2,
											},
											Statements: []ast.Statement{
												&ast.RestartStatement{
													Meta: &ast.Meta{
														Token: token.Token{
															Type:     token.RESTART,
															Literal:  "restart",
															Line:     7,
															Position: 3,
														},
														Leading:            comments(),
														Trailing:           comments(),
														Infix:              comments(),
														Nest:               2,
														PreviousEmptyLines: 0,
														EndLine:            7,
														EndPosition:        9,
													},
												},
											},
										},
									},
								},
								Alternative: &ast.ElseStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.ELSE,
											Literal:  "else",
											Line:     8,
											Position: 4,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            10,
										EndPosition:        2,
									},
									Consequence: &ast.BlockStatement{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.LEFT_BRACE,
												Literal:  "{",
												Line:     8,
												Position: 9,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            10,
											EndPosition:        2,
										},
										Statements: []ast.Statement{
											&ast.RestartStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.RESTART,
														Literal:  "restart",
														Line:     9,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            9,
													EndPosition:        9,
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
	})

	t.Run("if elsif else ", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	if (req.http.Host ~ "example.com") {
		restart;
	} elsif (req.http.X-Forwarded-For ~ "192.168.0.1") {
		restart;
	} else {
		restart;
	}
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
						Leading:            comments("// Subroutine"),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            11,
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
							EndLine:            11,
							EndPosition:        1,
						},
						Statements: []ast.Statement{
							&ast.IfStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.IF,
										Literal:  "if",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// Leading comment"),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            10,
									EndPosition:        2,
								},
								Keyword: "if",
								Condition: &ast.InfixExpression{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.Host",
											Line:     4,
											Position: 6,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        34,
									},
									Operator: "~",
									Left: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.Host",
												Line:     4,
												Position: 6,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        18,
										},
										Value: "req.http.Host",
									},
									Right: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "example.com",
												Line:     4,
												Position: 22,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        34,
										},
										Value: "example.com",
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.LEFT_BRACE,
											Literal:  "{",
											Line:     4,
											Position: 37,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            6,
										EndPosition:        2,
									},
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.RESTART,
													Literal:  "restart",
													Line:     5,
													Position: 3,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            5,
												EndPosition:        9,
											},
										},
									},
								},
								Another: []*ast.IfStatement{
									{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.ELSIF,
												Literal:  "elsif",
												Line:     6,
												Position: 4,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            8,
											EndPosition:        2,
										},
										Keyword: "elsif",
										Condition: &ast.InfixExpression{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.IDENT,
													Literal:  "req.http.X-Forwarded-For",
													Line:     6,
													Position: 11,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            6,
												EndPosition:        50,
											},
											Operator: "~",
											Left: &ast.Ident{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.IDENT,
														Literal:  "req.http.X-Forwarded-For",
														Line:     6,
														Position: 11,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               1,
													PreviousEmptyLines: 0,
													EndLine:            6,
													EndPosition:        34,
												},
												Value: "req.http.X-Forwarded-For",
											},
											Right: &ast.String{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.STRING,
														Literal:  "192.168.0.1",
														Line:     6,
														Position: 38,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               1,
													PreviousEmptyLines: 0,
													EndLine:            6,
													EndPosition:        50,
												},
												Value: "192.168.0.1",
											},
										},
										Consequence: &ast.BlockStatement{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.LEFT_BRACE,
													Literal:  "{",
													Line:     6,
													Position: 53,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            8,
												EndPosition:        2,
											},
											Statements: []ast.Statement{
												&ast.RestartStatement{
													Meta: &ast.Meta{
														Token: token.Token{
															Type:     token.RESTART,
															Literal:  "restart",
															Line:     7,
															Position: 3,
														},
														Leading:            comments(),
														Trailing:           comments(),
														Infix:              comments(),
														Nest:               2,
														PreviousEmptyLines: 0,
														EndLine:            7,
														EndPosition:        9,
													},
												},
											},
										},
									},
								},
								Alternative: &ast.ElseStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.ELSE,
											Literal:  "else",
											Line:     8,
											Position: 4,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            10,
										EndPosition:        2,
									},
									Consequence: &ast.BlockStatement{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.LEFT_BRACE,
												Literal:  "{",
												Line:     8,
												Position: 9,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            10,
											EndPosition:        2,
										},
										Statements: []ast.Statement{
											&ast.RestartStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.RESTART,
														Literal:  "restart",
														Line:     9,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            9,
													EndPosition:        9,
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
	})

	t.Run("Complex comments", func(t *testing.T) {
		input := `
sub vcl_recv {
	// a
	if /* b */ (/* c */req.http.Host /* d */~ /* e */"example.com"/* f */) /* g */{
		restart;
		// h
	} // i
	// j
	elsif /* k */(/* l */req.http.X-Forwarded-For /* m */ ~ /* n */"192.168.0.1" /* o */) // p
	{
		restart;
		// q
	}
	// r
	else /* s */ {
		restart;
		// t
	} // u
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
						EndLine:            19,
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
							EndLine:            19,
							EndPosition:        1,
						},
						Statements: []ast.Statement{
							&ast.IfStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.IF,
										Literal:  "if",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// a"),
									Trailing:           comments(),
									Infix:              comments("/* b */"),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            18,
									EndPosition:        2,
								},
								Keyword: "if",
								Condition: &ast.InfixExpression{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.Host",
											Line:     4,
											Position: 21,
										},
										Leading:            comments("/* c */"),
										Trailing:           comments("/* d */", "/* f */"),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        63,
									},
									Left: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.Host",
												Line:     4,
												Position: 21,
											},
											Leading:            comments("/* c */"),
											Trailing:           comments("/* d */"),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        33,
										},
										Value: "req.http.Host",
									},
									Operator: "~",
									Right: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "example.com",
												Line:     4,
												Position: 51,
											},
											Leading:            comments("/* e */"),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        63,
										},
										Value: "example.com",
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.LEFT_BRACE,
											Literal:  "{",
											Line:     4,
											Position: 80,
										},
										Leading:            comments("/* g */"),
										Trailing:           comments("// i"),
										Infix:              comments("// h"),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            7,
										EndPosition:        2,
									},
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.RESTART,
													Literal:  "restart",
													Line:     5,
													Position: 3,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            5,
												EndPosition:        9,
											},
										},
									},
								},
								Another: []*ast.IfStatement{
									{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.ELSIF,
												Literal:  "elsif",
												Line:     9,
												Position: 2,
											},
											Leading:            comments("// j"),
											Trailing:           comments(),
											Infix:              comments("/* k */"),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            13,
											EndPosition:        2,
										},
										Keyword: "elsif",
										Condition: &ast.InfixExpression{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.IDENT,
													Literal:  "req.http.X-Forwarded-For",
													Line:     9,
													Position: 23,
												},
												Leading:            comments("/* l */"),
												Trailing:           comments("/* m */", "/* o */"),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            9,
												EndPosition:        77,
											},
											Left: &ast.Ident{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.IDENT,
														Literal:  "req.http.X-Forwarded-For",
														Line:     9,
														Position: 23,
													},
													Leading:            comments("/* l */"),
													Trailing:           comments("/* m */"),
													Infix:              comments(),
													Nest:               1,
													PreviousEmptyLines: 0,
													EndLine:            9,
													EndPosition:        46,
												},
												Value: "req.http.X-Forwarded-For",
											},
											Operator: "~",
											Right: &ast.String{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.STRING,
														Literal:  "192.168.0.1",
														Line:     9,
														Position: 65,
													},
													Leading:            comments("/* n */"),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               1,
													PreviousEmptyLines: 0,
													EndLine:            9,
													EndPosition:        77,
												},
												Value: "192.168.0.1",
											},
										},
										Consequence: &ast.BlockStatement{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.LEFT_BRACE,
													Literal:  "{",
													Line:     10,
													Position: 2,
												},
												Leading:            comments("// p"),
												Trailing:           comments(),
												Infix:              comments("// q"),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            13,
												EndPosition:        2,
											},
											Statements: []ast.Statement{
												&ast.RestartStatement{
													Meta: &ast.Meta{
														Token: token.Token{
															Type:     token.RESTART,
															Literal:  "restart",
															Line:     11,
															Position: 3,
														},
														Leading:            comments(),
														Trailing:           comments(),
														Infix:              comments(),
														Nest:               2,
														PreviousEmptyLines: 0,
														EndLine:            11,
														EndPosition:        9,
													},
												},
											},
										},
									},
								},
								Alternative: &ast.ElseStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.ELSE,
											Literal:  "else",
											Line:     15,
											Position: 2,
										},
										Leading:            comments("// r"),
										Trailing:           comments(),
										Infix:              comments("/* s */"),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            18,
										EndPosition:        2,
									},
									Consequence: &ast.BlockStatement{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.LEFT_BRACE,
												Literal:  "{",
												Line:     15,
												Position: 15,
											},
											Leading:            comments(),
											Trailing:           comments("// u"),
											Infix:              comments("// t"),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            18,
											EndPosition:        2,
										},
										Statements: []ast.Statement{
											&ast.RestartStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.RESTART,
														Literal:  "restart",
														Line:     16,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            16,
													EndPosition:        9,
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
	})
}

func TestParseSwitchStatement(t *testing.T) {
	t.Run("basic switch statement", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Switch
	switch (req.http.host) {
	case "1":
		esi;
		break;
	default:
		esi;
		fallthrough;
	case ~/* infix */"[2-3]":
		esi;
		break;
	}
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
						Leading:            comments("// Subroutine"),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            15,
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
							EndLine:            15,
							EndPosition:        1,
						},
						Statements: []ast.Statement{
							&ast.SwitchStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.SWITCH,
										Literal:  "switch",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// Switch"),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            14,
									EndPosition:        2,
								},
								Control: &ast.SwitchControl{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.LEFT_PAREN,
											Literal:  "(",
											Line:     4,
											Position: 9,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        23,
									},
									Expression: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.host",
												Line:     4,
												Position: 10,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        22,
										},
										Value: "req.http.host",
									},
								},
								Default: 1,
								Cases: []*ast.CaseStatement{
									{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.CASE,
												Literal:  "case",
												Line:     5,
												Position: 2,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            8,
											EndPosition:        2,
										},
										Test: &ast.InfixExpression{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.STRING,
													Literal:  "1",
													Line:     5,
													Position: 7,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            5,
												EndPosition:        9,
											},
											Operator: "==",
											Right: &ast.String{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.STRING,
														Literal:  "1",
														Line:     5,
														Position: 7,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            5,
													EndPosition:        9,
												},
												Value: "1",
											},
										},
										Statements: []ast.Statement{
											&ast.EsiStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.ESI,
														Literal:  "esi",
														Line:     6,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            6,
													EndPosition:        5,
												},
											},
											&ast.BreakStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.BREAK,
														Literal:  "break",
														Line:     7,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            7,
													EndPosition:        7,
												},
											},
										},
									},
									{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.DEFAULT,
												Literal:  "default",
												Line:     8,
												Position: 2,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            11,
											EndPosition:        2,
										},
										Statements: []ast.Statement{
											&ast.EsiStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.ESI,
														Literal:  "esi",
														Line:     9,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            9,
													EndPosition:        5,
												},
											},
											&ast.FallthroughStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.FALLTHROUGH,
														Literal:  "fallthrough",
														Line:     10,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            10,
													EndPosition:        13,
												},
											},
										},
										Fallthrough: true,
									},
									{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.CASE,
												Literal:  "case",
												Line:     11,
												Position: 2,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments("/* infix */"),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            14,
											EndPosition:        2,
										},
										Test: &ast.InfixExpression{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.REGEX_MATCH,
													Literal:  "~",
													Line:     11,
													Position: 7,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            11,
												EndPosition:        25,
											},
											Operator: "~",
											Right: &ast.String{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.STRING,
														Literal:  "[2-3]",
														Line:     11,
														Position: 19,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            11,
													EndPosition:        25,
												},
												Value: "[2-3]",
											},
										},
										Statements: []ast.Statement{
											&ast.EsiStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.ESI,
														Literal:  "esi",
														Line:     12,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            12,
													EndPosition:        5,
												},
											},
											&ast.BreakStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.BREAK,
														Literal:  "break",
														Line:     13,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            13,
													EndPosition:        7,
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
	})

	t.Run("switch statement with function control statement", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Switch
	switch (uuid.version4()) {
	case "xxx-xxx-xxx":
		esi;
		break;
	}
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
						Leading:            comments("// Subroutine"),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            9,
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
							EndLine:            9,
							EndPosition:        1,
						},
						Statements: []ast.Statement{
							&ast.SwitchStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.SWITCH,
										Literal:  "switch",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// Switch"),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            8,
									EndPosition:        2,
								},
								Control: &ast.SwitchControl{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.LEFT_PAREN,
											Literal:  "(",
											Line:     4,
											Position: 9,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        25,
									},
									Expression: &ast.FunctionCallExpression{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "uuid.version4",
												Line:     4,
												Position: 10,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        24,
										},
										Function: &ast.Ident{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.IDENT,
													Literal:  "uuid.version4",
													Line:     4,
													Position: 10,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            4,
												EndPosition:        22,
											},
											Value: "uuid.version4",
										},
										Arguments: []ast.Expression{},
									},
								},
								Default: -1,
								Cases: []*ast.CaseStatement{
									{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.CASE,
												Literal:  "case",
												Line:     5,
												Position: 2,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            8,
											EndPosition:        2,
										},
										Test: &ast.InfixExpression{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.STRING,
													Literal:  "xxx-xxx-xxx",
													Line:     5,
													Position: 7,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            5,
												EndPosition:        19,
											},
											Operator: "==",
											Right: &ast.String{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.STRING,
														Literal:  "xxx-xxx-xxx",
														Line:     5,
														Position: 7,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            5,
													EndPosition:        19,
												},
												Value: "xxx-xxx-xxx",
											},
										},
										Statements: []ast.Statement{
											&ast.EsiStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.ESI,
														Literal:  "esi",
														Line:     6,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            6,
													EndPosition:        5,
												},
											},
											&ast.BreakStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.BREAK,
														Literal:  "break",
														Line:     7,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            7,
													EndPosition:        7,
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
	})

	t.Run("switch statement with bool literal control statement", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Switch
	switch (true) {
	case "1":
		esi;
		break;
	default:
		esi;
		break;
	}
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
						Leading:            comments("// Subroutine"),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            12,
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
							EndLine:            12,
							EndPosition:        1,
						},
						Statements: []ast.Statement{
							&ast.SwitchStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.SWITCH,
										Literal:  "switch",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// Switch"),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            11,
									EndPosition:        2,
								},
								Control: &ast.SwitchControl{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.LEFT_PAREN,
											Literal:  "(",
											Line:     4,
											Position: 9,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        14,
									},
									Expression: &ast.Boolean{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.TRUE,
												Literal:  "true",
												Line:     4,
												Position: 10,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        13,
										},
										Value: true,
									},
								},
								Default: 1,
								Cases: []*ast.CaseStatement{
									{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.CASE,
												Literal:  "case",
												Line:     5,
												Position: 2,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            8,
											EndPosition:        2,
										},
										Test: &ast.InfixExpression{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.STRING,
													Literal:  "1",
													Line:     5,
													Position: 7,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            5,
												EndPosition:        9,
											},
											Operator: "==",
											Right: &ast.String{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.STRING,
														Literal:  "1",
														Line:     5,
														Position: 7,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            5,
													EndPosition:        9,
												},
												Value: "1",
											},
										},
										Statements: []ast.Statement{
											&ast.EsiStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.ESI,
														Literal:  "esi",
														Line:     6,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            6,
													EndPosition:        5,
												},
											},
											&ast.BreakStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.BREAK,
														Literal:  "break",
														Line:     7,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            7,
													EndPosition:        7,
												},
											},
										},
									},
									{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.DEFAULT,
												Literal:  "default",
												Line:     8,
												Position: 2,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            11,
											EndPosition:        2,
										},
										Statements: []ast.Statement{
											&ast.EsiStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.ESI,
														Literal:  "esi",
														Line:     9,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            9,
													EndPosition:        5,
												},
											},
											&ast.BreakStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.BREAK,
														Literal:  "break",
														Line:     10,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            10,
													EndPosition:        7,
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
	})

	t.Run("float literal as control should fail", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Switch
	switch (1.0) {
	case "1.00":
		esi;
	default:
		esi;
		break;
	}
}`
		_, err := New(lexer.NewFromString(input)).ParseVCL()
		if err == nil {
			t.Errorf("expected error")
		}
	})

	t.Run("case with missing break should fail", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Switch
	switch (req.http.host) {
	case "1":
		esi;
	default:
		esi;
		break;
	}
}`
		_, err := New(lexer.NewFromString(input)).ParseVCL()
		if err == nil {
			t.Errorf("expected error")
		}
	})

	t.Run("duplicate cases should should fail", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Switch
	switch (req.http.host) {
	case "1":
		esi;
		break;
	case "1":
		esi;
		break;
	}
}`
		_, err := New(lexer.NewFromString(input)).ParseVCL()
		if err == nil {
			t.Errorf("expected error")
		}
	})

	t.Run("duplicate default cases should fail", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Switch
	switch (req.http.host) {
	default:
		esi;
		break;
	default:
		esi;
		break;
	}
}`
		_, err := New(lexer.NewFromString(input)).ParseVCL()
		if err == nil {
			t.Errorf("expected error")
		}
	})

	t.Run("case with non-string match expression should fail", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Switch
	switch (req.http.host) {
	case 1:
		esi;
		break;
	}
}`
		_, err := New(lexer.NewFromString(input)).ParseVCL()
		if err == nil {
			t.Errorf("expected error")
		}
	})
	t.Run("fallthrough on final case should fail", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Switch
	switch (req.http.host) {
	case "1":
		esi;
		fallthrough;
	}
}`
		_, err := New(lexer.NewFromString(input)).ParseVCL()
		if err == nil {
			t.Errorf("expected error")
		}
	})

	t.Run("break in nested block statement should fail", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Switch
	switch (req.http.host) {
	case "1":
		if ("") { break; }
		esi;
		break;
	}
}`
		_, err := New(lexer.NewFromString(input)).ParseVCL()
		if err == nil {
			t.Errorf("expected error")
		}
	})

	t.Run("Full comments", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// a
	switch /* b */(/* c */req.http.Host /* d */) /* e */{
	// f
	case /* g */"1" /* h */: // i
		esi;
		// j
		break /* k */; // l
	// m
	default /* n */: // o
		esi;
		break;
	// p
	} // q
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
						Leading:            comments("// Subroutine"),
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
							EndLine:            16,
							EndPosition:        1,
						},
						Statements: []ast.Statement{
							&ast.SwitchStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.SWITCH,
										Literal:  "switch",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// a"),
									Trailing:           comments("// q"),
									Infix:              comments("// p"),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            15,
									EndPosition:        2,
								},
								Control: &ast.SwitchControl{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.LEFT_PAREN,
											Literal:  "(",
											Line:     4,
											Position: 16,
										},
										Leading:            comments("/* b */"),
										Trailing:           comments("/* e */"),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        45,
									},
									Expression: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.Host",
												Line:     4,
												Position: 24,
											},
											Leading:            comments("/* c */"),
											Trailing:           comments("/* d */"),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        36,
										},
										Value: "req.http.Host",
									},
								},
								Default: 1,
								Cases: []*ast.CaseStatement{
									{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.CASE,
												Literal:  "case",
												Line:     6,
												Position: 2,
											},
											Leading:            comments("// f"),
											Trailing:           comments("// i"),
											Infix:              comments("/* g */"),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            11,
											EndPosition:        2,
										},
										Test: &ast.InfixExpression{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.STRING,
													Literal:  "1",
													Line:     6,
													Position: 14,
												},
												Leading:            comments(),
												Trailing:           comments("/* h */"),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            6,
												EndPosition:        16,
											},
											Operator: "==",
											Right: &ast.String{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.STRING,
														Literal:  "1",
														Line:     6,
														Position: 14,
													},
													Leading:            comments(),
													Trailing:           comments("/* h */"),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            6,
													EndPosition:        16,
												},
												Value: "1",
											},
										},
										Statements: []ast.Statement{
											&ast.EsiStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.ESI,
														Literal:  "esi",
														Line:     7,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            7,
													EndPosition:        5,
												},
											},
											&ast.BreakStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.BREAK,
														Literal:  "break",
														Line:     9,
														Position: 3,
													},
													Leading:            comments("// j"),
													Trailing:           comments("// l"),
													Infix:              comments("/* k */"),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            9,
													EndPosition:        7,
												},
											},
										},
									},
									{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.DEFAULT,
												Literal:  "default",
												Line:     11,
												Position: 2,
											},
											Leading:            comments("// m"),
											Trailing:           comments("// o"),
											Infix:              comments("/* n */"),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            15,
											EndPosition:        2,
										},
										Statements: []ast.Statement{
											&ast.EsiStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.ESI,
														Literal:  "esi",
														Line:     12,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            12,
													EndPosition:        5,
												},
											},
											&ast.BreakStatement{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.BREAK,
														Literal:  "break",
														Line:     13,
														Position: 3,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            13,
													EndPosition:        7,
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
	})
}

func TestParseUnsetStatement(t *testing.T) {
	input := `// Subroutine
sub vcl_recv {
	// Leading comment
	unset /* Infix1 */ req.http.Host /* Infix2 */; // Trailing comment
}`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.SubroutineDeclaration{
				Meta: ast.New(T, 0, comments("// Subroutine")),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "vcl_recv",
				},
				Block: &ast.BlockStatement{
					Meta: ast.New(T, 1),
					Statements: []ast.Statement{
						&ast.UnsetStatement{
							Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
							Ident: &ast.Ident{
								Meta:  ast.New(T, 1, comments("/* Infix1 */"), comments("/* Infix2 */")),
								Value: "req.http.Host",
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

func TestParseAddStatement(t *testing.T) {
	t.Run("simple assign", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	add /* a */ req.http.Cookie:session /* b */= /* c */ "example.com" /* d */; // Trailing comment
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
						Leading:            comments("// Subroutine"),
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
							&ast.AddStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.ADD,
										Literal:  "add",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// Leading comment"),
									Trailing:           comments("// Trailing comment"),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            4,
									EndPosition:        67,
								},
								Ident: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.Cookie:session",
											Line:     4,
											Position: 14,
										},
										Leading:            comments("/* a */"),
										Trailing:           comments("/* b */"),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        36,
									},
									Value: "req.http.Cookie:session",
								},
								Operator: &ast.Operator{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.ASSIGN,
											Literal:  "=",
											Line:     4,
											Position: 45,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        45,
									},
									Operator: "=",
								},
								Value: &ast.String{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.STRING,
											Literal:  "example.com",
											Line:     4,
											Position: 55,
										},
										Leading:            comments("/* c */"),
										Trailing:           comments("/* d */"),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        67,
									},
									Value: "example.com",
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
	})

	t.Run("with string concatenation", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	add req.http.Host = "example" req.http.User-Agent "com"; // Trailing comment
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
						Leading:            comments("// Subroutine"),
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
							&ast.AddStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.ADD,
										Literal:  "add",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// Leading comment"),
									Trailing:           comments("// Trailing comment"),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            4,
									EndPosition:        56,
								},
								Ident: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.Host",
											Line:     4,
											Position: 6,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        18,
									},
									Value: "req.http.Host",
								},
								Operator: &ast.Operator{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.ASSIGN,
											Literal:  "=",
											Line:     4,
											Position: 20,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        20,
									},
									Operator: "=",
								},
								Value: &ast.InfixExpression{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.STRING,
											Literal:  "example",
											Line:     4,
											Position: 22,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        56,
									},
									Operator: "+",
									Left: &ast.InfixExpression{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "example",
												Line:     4,
												Position: 22,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        50,
										},
										Operator: "+",
										Left: &ast.String{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.STRING,
													Literal:  "example",
													Line:     4,
													Position: 22,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            4,
												EndPosition:        30,
											},
											Value: "example",
										},
										Right: &ast.Ident{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.IDENT,
													Literal:  "req.http.User-Agent",
													Line:     4,
													Position: 32,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            4,
												EndPosition:        50,
											},
											Value: "req.http.User-Agent",
										},
									},
									Right: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "com",
												Line:     4,
												Position: 52,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        56,
										},
										Value: "com",
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
	})
}

func TestCallStatement(t *testing.T) {
	t.Run("without parentheses", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	call /* a */ feature_mod_recv /* b */; // Trailing comment
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
						Leading:            comments("// Subroutine"),
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
							&ast.CallStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.CALL,
										Literal:  "call",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// Leading comment"),
									Trailing:           comments("// Trailing comment"),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            4,
									EndPosition:        30,
								},
								Subroutine: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "feature_mod_recv",
											Line:     4,
											Position: 15,
										},
										Leading:            comments("/* a */"),
										Trailing:           comments("/* b */"),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        30,
									},
									Value: "feature_mod_recv",
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
	})

	t.Run("with parentheses", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	call /* a */feature_mod_recv() /* b */; // Trailing comment
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
						Leading:            comments("// Subroutine"),
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
							&ast.CallStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.CALL,
										Literal:  "call",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// Leading comment"),
									Trailing:           comments("// Trailing comment"),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            4,
									EndPosition:        31,
								},
								Subroutine: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "feature_mod_recv",
											Line:     4,
											Position: 14,
										},
										Leading:            comments("/* a */"),
										Trailing:           comments("/* b */"),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        31,
									},
									Value: "feature_mod_recv",
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
	})
}

func TestDeclareStatement(t *testing.T) {
	t.Run("Basic parse", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	declare local var.foo STRING; // Trailing comment
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
						Leading:            comments("// Subroutine"),
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
							&ast.DeclareStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.DECLARE,
										Literal:  "declare",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// Leading comment"),
									Trailing:           comments("// Trailing comment"),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            4,
									EndPosition:        29,
								},
								Name: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "var.foo",
											Line:     4,
											Position: 16,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        22,
									},
									Value: "var.foo",
								},
								ValueType: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "STRING",
											Line:     4,
											Position: 24,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        29,
									},
									Value: "STRING",
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
	})
	t.Run("Full comments", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// a
	declare /* b */ local /* c */var.foo /* d */STRING /* e */; // e
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
						Leading:            comments("// Subroutine"),
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
							&ast.DeclareStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.DECLARE,
										Literal:  "declare",
										Line:     4,
										Position: 2,
									},
									Leading:            comments("// a"),
									Trailing:           comments("// e"),
									Infix:              comments("/* b */"),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            4,
									EndPosition:        51,
								},
								Name: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "var.foo",
											Line:     4,
											Position: 31,
										},
										Leading:            comments("/* c */"),
										Trailing:           comments("/* d */"),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        37,
									},
									Value: "var.foo",
								},
								ValueType: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "STRING",
											Line:     4,
											Position: 46,
										},
										Leading:            comments(),
										Trailing:           comments("/* e */"),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        51,
									},
									Value: "STRING",
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
	})
}

func TestErrorStatement(t *testing.T) {
	t.Run("without argument", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	error 750; // Trailing comment
}`
		expect := &ast.VCL{
			Statements: []ast.Statement{
				&ast.SubroutineDeclaration{
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.ErrorStatement{
								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
								Code: &ast.Integer{
									Meta:  ast.New(T, 1),
									Value: 750,
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
	})

	t.Run("with argument", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	error 750 "/foobar/" req.http.Foo; // Trailing comment
}`
		expect := &ast.VCL{
			Statements: []ast.Statement{
				&ast.SubroutineDeclaration{
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.ErrorStatement{
								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
								Code: &ast.Integer{
									Meta:  ast.New(T, 1),
									Value: 750,
								},
								Argument: &ast.InfixExpression{
									Meta: ast.New(T, 1),
									Left: &ast.String{
										Meta:  ast.New(T, 1),
										Value: "/foobar/",
									},
									Operator: "+",
									Right: &ast.Ident{
										Meta:  ast.New(T, 1),
										Value: "req.http.Foo",
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
	})

	t.Run("with ident argument", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	error var.IntValue; // Trailing comment
}`
		expect := &ast.VCL{
			Statements: []ast.Statement{
				&ast.SubroutineDeclaration{
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.ErrorStatement{
								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
								Code: &ast.Ident{
									Meta:  ast.New(T, 1),
									Value: "var.IntValue",
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
	})

	t.Run("with function argument", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	error table.lookup_integer(errors, "foo", 600) "bar"; // Trailing comment
}`
		expect := &ast.VCL{
			Statements: []ast.Statement{
				&ast.SubroutineDeclaration{
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.ErrorStatement{
								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
								Code: &ast.FunctionCallExpression{
									Meta: ast.New(T, 1),
									Function: &ast.Ident{
										Meta:  ast.New(T, 1),
										Value: "table.lookup_integer",
									},
									Arguments: []ast.Expression{
										&ast.Ident{
											Meta:  ast.New(T, 1),
											Value: "errors",
										},
										&ast.String{
											Meta:  ast.New(T, 1),
											Value: "foo",
										},
										&ast.Integer{
											Meta:  ast.New(T, 1),
											Value: 600,
										},
									},
								},
								Argument: &ast.String{
									Meta:  ast.New(T, 1),
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
	})

	t.Run("Full comments without argument", func(t *testing.T) {
		input := `sub vcl_recv {
	// a
	error /* b */ 750 /* c */; // d
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
								Meta: ast.New(T, 1, comments("// a"), comments("// d")),
								Code: &ast.Integer{
									Meta:  ast.New(T, 1, comments("/* b */"), comments("/* c */")),
									Value: 750,
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
	})

	t.Run("Full comments with arguments", func(t *testing.T) {
		input := `sub vcl_recv {
	// a
	error /* b */ 750 /* c */"/foobar/" /* d */ req.http.Foo /* e */; // f
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
								Meta: ast.New(T, 1, comments("// a"), comments("// f")),
								Code: &ast.Integer{
									Meta:  ast.New(T, 1, comments("/* b */")),
									Value: 750,
								},
								Argument: &ast.InfixExpression{
									Meta: ast.New(T, 1, comments(), comments("/* e */")),
									Left: &ast.String{
										Meta:  ast.New(T, 1, comments("/* c */"), comments("/* d */")),
										Value: "/foobar/",
									},
									Operator: "+",
									Right: &ast.Ident{
										Meta:  ast.New(T, 1, comments(), comments("/* e */")),
										Value: "req.http.Foo",
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
	})
}

func TestLogStatement(t *testing.T) {
	input := `// Subroutine
sub vcl_recv {
	// Leading comment
	log /* a */ {"syslog "} // b
		{" fastly-log :: "} /* c */ {"	timestamp:"}
		req.http.Timestamp // d
	; // Trailing comment
}`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.SubroutineDeclaration{
				Meta: ast.New(T, 0, comments("// Subroutine")),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "vcl_recv",
				},
				Block: &ast.BlockStatement{
					Meta: ast.New(T, 1),
					Statements: []ast.Statement{
						&ast.LogStatement{
							Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
							Value: &ast.InfixExpression{
								Meta:     ast.New(T, 1, comments(), comments("// d")),
								Operator: "+",
								Right: &ast.Ident{
									Meta:  ast.New(T, 1, comments(), comments("// d")),
									Value: "req.http.Timestamp",
								},
								Left: &ast.InfixExpression{
									Meta:     ast.New(T, 1),
									Operator: "+",
									Right: &ast.String{
										Meta: ast.New(T, 1),
										Value: "	timestamp:",
										LongString: true,
									},
									Left: &ast.InfixExpression{
										Meta:     ast.New(T, 1, comments(), comments("/* c */")),
										Operator: "+",
										Right: &ast.String{
											Meta:       ast.New(T, 1, comments(), comments("/* c */")),
											Value:      " fastly-log :: ",
											LongString: true,
										},
										Left: &ast.String{
											Meta:       ast.New(T, 1, comments("/* a */"), comments("// b")),
											Value:      "syslog ",
											LongString: true,
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

func TestReturnStatement(t *testing.T) {
	t.Run("Basic parse", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	return(deliver); // Trailing comment
}`
		expect := &ast.VCL{
			Statements: []ast.Statement{
				&ast.SubroutineDeclaration{
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.ReturnStatement{
								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
								ReturnExpression: &ast.Ident{
									Meta:  ast.New(T, 1),
									Value: "deliver",
								},
								HasParenthesis:              true,
								ParenthesisLeadingComments:  comments(),
								ParenthesisTrailingComments: comments(),
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
	})

	t.Run("Full comments", func(t *testing.T) {
		input := `sub vcl_recv {
	// a
	return /* b */(/* c */lookup/* d */)/* e */; // f
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
							&ast.ReturnStatement{
								Meta: ast.New(T, 1, comments("// a"), comments("// f")),
								ReturnExpression: &ast.Ident{
									Meta:  ast.New(T, 1, comments("/* c */"), comments("/* d */")),
									Value: "lookup",
								},
								HasParenthesis:              true,
								ParenthesisLeadingComments:  comments("/* b */"),
								ParenthesisTrailingComments: comments("/* e */"),
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
	})
}

func TestSyntheticStatement(t *testing.T) {
	t.Run("Basic parse", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	synthetic {"Access "}
		{"denied"}; // Trailing comment
}`
		expect := &ast.VCL{
			Statements: []ast.Statement{
				&ast.SubroutineDeclaration{
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.SyntheticStatement{
								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
								Value: &ast.InfixExpression{
									Meta: ast.New(T, 1),
									Left: &ast.String{
										Meta:       ast.New(T, 1),
										Value:      "Access ",
										LongString: true,
									},
									Operator: "+",
									Right: &ast.String{
										Meta:       ast.New(T, 1),
										Value:      "denied",
										LongString: true,
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
	})

	t.Run("Full comments", func(t *testing.T) {
		input := `sub vcl_recv {
	// a
	synthetic /* b */ {"Access "} // c
		/* d */ {"denied"} /* e */; // f
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
							&ast.SyntheticStatement{
								Meta: ast.New(T, 1, comments("// a"), comments("// f")),
								Value: &ast.InfixExpression{
									Meta: ast.New(T, 1, comments(), comments("/* e */")),
									Left: &ast.String{
										Meta:       ast.New(T, 1, comments("/* b */"), comments("// c", "/* d */")),
										Value:      "Access ",
										LongString: true,
									},
									Operator: "+",
									Right: &ast.String{
										Meta:       ast.New(T, 1, comments(), comments("/* e */")),
										Value:      "denied",
										LongString: true,
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
	})
}

func TestSyntheticBase64Statement(t *testing.T) {
	t.Run("Basic parse", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	synthetic.base64 {"Access "}
		{"denied"}; // Trailing comment
}`
		expect := &ast.VCL{
			Statements: []ast.Statement{
				&ast.SubroutineDeclaration{
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.SyntheticBase64Statement{
								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
								Value: &ast.InfixExpression{
									Meta: ast.New(T, 1),
									Left: &ast.String{
										Meta:       ast.New(T, 1),
										Value:      "Access ",
										LongString: true,
									},
									Operator: "+",
									Right: &ast.String{
										Meta:       ast.New(T, 1),
										Value:      "denied",
										LongString: true,
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
	})

	t.Run("Full comments", func(t *testing.T) {
		input := `sub vcl_recv {
	// a
	synthetic.base64 /* b */ {"Access "} // c
		/* d */ {"denied"} /* e */; // f
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
							&ast.SyntheticBase64Statement{
								Meta: ast.New(T, 1, comments("// a"), comments("// f")),
								Value: &ast.InfixExpression{
									Meta: ast.New(T, 1, comments(), comments("/* e */")),
									Left: &ast.String{
										Meta:       ast.New(T, 1, comments("/* b */"), comments("// c", "/* d */")),
										Value:      "Access ",
										LongString: true,
									},
									Operator: "+",
									Right: &ast.String{
										Meta:       ast.New(T, 1, comments(), comments("/* e */")),
										Value:      "denied",
										LongString: true,
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
	})
}

func TestBlockSyntaxInsideBlockStatement(t *testing.T) {
	t.Run("nested block", func(t *testing.T) {
		input := `
sub vcl_recv {
	{
		log "vcl_recv";
	}
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
							&ast.BlockStatement{
								Meta: ast.New(T, 2),
								Statements: []ast.Statement{
									&ast.LogStatement{
										Meta: ast.New(T, 2),
										Value: &ast.String{
											Meta:  ast.New(T, 2),
											Value: "vcl_recv",
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
	})

	t.Run("nested two blocks", func(t *testing.T) {
		input := `
sub vcl_recv {
	{
		{
			log "vcl_recv";
		}
	}
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
							&ast.BlockStatement{
								Meta: ast.New(T, 2),
								Statements: []ast.Statement{
									&ast.BlockStatement{
										Meta: ast.New(T, 3),
										Statements: []ast.Statement{
											&ast.LogStatement{
												Meta: ast.New(T, 3),
												Value: &ast.String{
													Meta:  ast.New(T, 3),
													Value: "vcl_recv",
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
	})

	t.Run("nested blocks with comments", func(t *testing.T) {
		input := `
sub vcl_recv {
	// Block Leading comment
	{
		log "vcl_recv";
		// Block Infix comment
	} // Block Trailing comment
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
							&ast.BlockStatement{
								Meta: ast.New(T, 2, comments("// Block Leading comment"), comments("// Block Trailing comment"), comments("// Block Infix comment")),
								Statements: []ast.Statement{
									&ast.LogStatement{
										Meta: ast.New(T, 2),
										Value: &ast.String{
											Meta:  ast.New(T, 2),
											Value: "vcl_recv",
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
	})
}

func TestGotoStatement(t *testing.T) {
	t.Run("goto statement", func(t *testing.T) {
		input := `// Goto Statement
		sub vcl_recv {
			// Leading comment
			goto update_and_set; // Trailing comment
		}`
		expect := &ast.VCL{
			Statements: []ast.Statement{
				&ast.SubroutineDeclaration{
					Meta: ast.New(T, 0, comments("// Goto Statement")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.GotoStatement{
								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
								Destination: &ast.Ident{
									Meta:  ast.New(T, 1),
									Value: "update_and_set",
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
	})

	t.Run("goto destination as IDENT", func(t *testing.T) {
		input := `// Goto Statement
		sub vcl_recv {
			// Leading comment
			goto update_and_set; // Trailing comment
			update_and_set:
		}`
		expect := &ast.VCL{
			Statements: []ast.Statement{
				&ast.SubroutineDeclaration{
					Meta: ast.New(T, 0, comments("// Goto Statement")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.GotoStatement{
								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
								Destination: &ast.Ident{
									Meta:  ast.New(T, 1),
									Value: "update_and_set",
								},
							},
							&ast.GotoDestinationStatement{
								Meta: ast.New(T, 1),
								Name: &ast.Ident{
									Meta:  ast.New(T, 1),
									Value: "update_and_set:",
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
	})

	t.Run("Full comments", func(t *testing.T) {
		input := `sub vcl_recv {
			// a
			goto /* b */update_and_set /* c */; // d
			// e
			update_and_set: // g
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
							&ast.GotoStatement{
								Meta: ast.New(T, 1, comments("// a"), comments("// d")),
								Destination: &ast.Ident{
									Meta:  ast.New(T, 1, comments("/* b */"), comments("/* c */")),
									Value: "update_and_set",
								},
							},
							&ast.GotoDestinationStatement{
								Meta: ast.New(T, 1, comments("// e"), comments("// g")),
								Name: &ast.Ident{
									Meta:  ast.New(T, 1, comments("// e"), comments("// g")),
									Value: "update_and_set:",
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
	})
}

func TestFunctionCallStatement(t *testing.T) {
	t.Run("normal function call without arguments", func(t *testing.T) {
		input := `
sub vcl_recv {
	// Function Leading comment
	testFun(); // Function Trailing comment
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
							&ast.FunctionCallStatement{
								Meta: ast.New(T, 1, comments("// Function Leading comment"), comments("// Function Trailing comment")),
								Function: &ast.Ident{
									Meta:  ast.New(T, 1, comments("// Function Leading comment"), comments("// Function Trailing comment")),
									Value: "testFun",
								},
								Arguments: []ast.Expression{},
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
	})

	t.Run("normal function call with arguments", func(t *testing.T) {
		input := `
sub vcl_recv {
	testFun(test1, "test2", 3);
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
							&ast.FunctionCallStatement{
								Meta: ast.New(T, 1),
								Function: &ast.Ident{
									Meta:  ast.New(T, 1),
									Value: "testFun",
								},
								Arguments: []ast.Expression{
									&ast.Ident{
										Meta:  ast.New(T, 1),
										Value: "test1",
									},
									&ast.String{
										Meta:  ast.New(T, 1),
										Value: "test2",
									},
									&ast.Integer{
										Meta:  ast.New(T, 1),
										Value: 3,
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
	})

	t.Run("method call with arguments", func(t *testing.T) {
		input := `
sub vcl_recv {
	std.collect(test1, "test2", 3);
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
							&ast.FunctionCallStatement{
								Meta: ast.New(T, 1),
								Function: &ast.Ident{
									Meta:  ast.New(T, 1),
									Value: "std.collect",
								},
								Arguments: []ast.Expression{
									&ast.Ident{
										Meta:  ast.New(T, 1),
										Value: "test1",
									},
									&ast.String{
										Meta:  ast.New(T, 1),
										Value: "test2",
									},
									&ast.Integer{
										Meta:  ast.New(T, 1),
										Value: 3,
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
	})

	t.Run("Full comments", func(t *testing.T) {
		input := `
sub vcl_recv {
	// a
	std.collect(/* b */test1 /* c */, /* d */"test2" /* e */, /* f */3 /* g */) /* h */; // i
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
							&ast.FunctionCallStatement{
								Meta: ast.New(T, 1, comments("// a"), comments("// i"), comments("/* h */")),
								Function: &ast.Ident{
									Meta:  ast.New(T, 1, comments("// a"), comments("// i"), comments("/* h */")),
									Value: "std.collect",
								},
								Arguments: []ast.Expression{
									&ast.Ident{
										Meta:  ast.New(T, 1, comments("/* b */"), comments("/* c */")),
										Value: "test1",
									},
									&ast.String{
										Meta:  ast.New(T, 1, comments("/* d */"), comments("/* e */")),
										Value: "test2",
									},
									&ast.Integer{
										Meta:  ast.New(T, 1, comments("/* f */"), comments("/* g */")),
										Value: 3,
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
	})
}
