package parser

import (
	"fmt"
	"testing"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/token"
)

func TestParseImport(t *testing.T) {
	input := `// Leading comment
import boltsort; // Trailing comment`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.ImportStatement{
				Meta: ast.New(T, 0, comments("// Leading comment"), comments("// Trailing comment")),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "boltsort",
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

func TestParseInclude(t *testing.T) {
	t.Run("with semicolon at the end", func(t *testing.T) {
		input := `// Leading comment
include "feature_mod"; // Trailing comment`
		expect := &ast.VCL{
			Statements: []ast.Statement{
				&ast.IncludeStatement{
					Meta: ast.New(T, 0, comments("// Leading comment"), comments("// Trailing comment")),
					Module: &ast.String{
						Meta:  ast.New(token.Token{}, 0),
						Value: "feature_mod",
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

	t.Run("without semicolon at the end", func(t *testing.T) {
		input := `// Leading comment
include "feature_mod" // Trailing comment`
		expect := &ast.VCL{
			Statements: []ast.Statement{
				&ast.IncludeStatement{
					Meta: ast.New(T, 0, comments("// Leading comment"), comments("// Trailing comment")),
					Module: &ast.String{
						Meta:  ast.New(token.Token{}, 0),
						Value: "feature_mod",
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
func TestParseSetStatement(t *testing.T) {
	t.Run("simple assign", func(t *testing.T) {
		operators := []string{
			"=",                    // simple assign
			"+=", "-=", "*=", "/=", // arithmetic ops
			"%=", "|=", "&=", "^=", // bitwise ops
			"<<=", ">>=", "rol=", "ror=", // bitwise shifts
			"||=", "&&=", // boolean
		}
		for _, op := range operators {
			input := fmt.Sprintf(`// Subroutine
				sub vcl_recv {
					// Leading comment
					set /* Host */ req.http.Host %s "example.com"; // Trailing comment
				}`,
				op)
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
								&ast.SetStatement{
									Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
									Ident: &ast.Ident{
										Meta:  ast.New(T, 1, comments("/* Host */")),
										Value: "req.http.Host",
									},
									Operator: &ast.Operator{
										Meta:     ast.New(T, 1),
										Operator: op,
									},
									Value: &ast.String{
										Meta:  ast.New(T, 1),
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
		input := `// Subroutine
	sub vcl_recv {
		// Leading comment
		set /* Host */ req.http.Host = "example." req.http.User-Agent ".com"; // Trailing comment
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
							&ast.SetStatement{
								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
								Ident: &ast.Ident{
									Meta:  ast.New(T, 1, comments("/* Host */")),
									Value: "req.http.Host",
								},
								Operator: &ast.Operator{
									Meta:     ast.New(T, 1),
									Operator: "=",
								},
								Value: &ast.InfixExpression{
									Meta:     ast.New(T, 1),
									Operator: "+",
									Left: &ast.InfixExpression{
										Meta:     ast.New(T, 1),
										Operator: "+",
										Left: &ast.String{
											Meta:  ast.New(T, 1),
											Value: "example.",
										},
										Right: &ast.Ident{
											Meta:  ast.New(T, 1),
											Value: "req.http.User-Agent",
										},
									},
									Right: &ast.String{
										Meta:  ast.New(T, 1),
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
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.IfStatement{
								Meta: ast.New(T, 1, comments("// Leading comment")),
								Condition: &ast.InfixExpression{
									Meta:     ast.New(T, 1),
									Operator: "~",
									Left: &ast.Ident{
										Meta:  ast.New(T, 1),
										Value: "req.http.Host",
									},
									Right: &ast.String{
										Meta:  ast.New(T, 1, comments("/* infix */")),
										Value: "example.com",
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: ast.New(T, 2, comments(), comments("// Trailing comment")),
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: ast.New(T, 2),
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
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.IfStatement{
								Meta: ast.New(T, 1, comments("// Leading comment")),
								Condition: &ast.InfixExpression{
									Meta:     ast.New(T, 1),
									Operator: "&&",
									Left: &ast.InfixExpression{
										Meta:     ast.New(T, 1),
										Operator: "~",
										Left: &ast.Ident{
											Meta:  ast.New(T, 1),
											Value: "req.http.Host",
										},
										Right: &ast.String{
											Meta:  ast.New(T, 1),
											Value: "example.com",
										},
									},
									Right: &ast.InfixExpression{
										Meta:     ast.New(T, 1),
										Operator: "==",
										Left: &ast.Ident{
											Meta:  ast.New(T, 1, comments("/* infix */")),
											Value: "req.http.Host",
										},
										Right: &ast.String{
											Meta:  ast.New(T, 1),
											Value: "foobar",
										},
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: ast.New(T, 2, comments(), comments("// Trailing comment")),
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: ast.New(T, 2),
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
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.IfStatement{
								Meta: ast.New(T, 1, comments("// Leading comment")),
								Condition: &ast.InfixExpression{
									Meta:     ast.New(T, 1),
									Operator: "||",
									Left: &ast.InfixExpression{
										Meta:     ast.New(T, 1),
										Operator: "~",
										Left: &ast.Ident{
											Meta:  ast.New(T, 1),
											Value: "req.http.Host",
										},
										Right: &ast.String{
											Meta:  ast.New(T, 1),
											Value: "example.com",
										},
									},
									Right: &ast.InfixExpression{
										Meta:     ast.New(T, 1),
										Operator: "==",
										Left: &ast.Ident{
											Meta:  ast.New(T, 1),
											Value: "req.http.Host",
										},
										Right: &ast.String{
											Meta:  ast.New(T, 1),
											Value: "foobar",
										},
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: ast.New(T, 2),
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: ast.New(T, 2),
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
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.IfStatement{
								Meta: ast.New(T, 1, comments("// Leading comment")),
								Condition: &ast.InfixExpression{
									Meta:     ast.New(T, 1),
									Operator: "||",
									Left: &ast.Boolean{
										Meta:  ast.New(T, 1),
										Value: true,
									},
									Right: &ast.InfixExpression{
										Meta:     ast.New(T, 1),
										Operator: "&&",
										Left: &ast.Boolean{
											Meta:  ast.New(T, 1),
											Value: false,
										},
										Right: &ast.Boolean{
											Meta:  ast.New(T, 1),
											Value: false,
										},
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: ast.New(T, 2),
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: ast.New(T, 2),
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
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.IfStatement{
								Meta: ast.New(T, 1, comments("// Leading comment")),
								Condition: &ast.InfixExpression{
									Meta:     ast.New(T, 1),
									Operator: "~",
									Left: &ast.Ident{
										Meta:  ast.New(T, 1),
										Value: "req.http.Host",
									},
									Right: &ast.String{
										Meta:  ast.New(T, 1),
										Value: "example.com",
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: ast.New(T, 2),
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: ast.New(T, 2),
										},
									},
								},
								AlternativeComments: comments("// Leading comment"),
								Alternative: &ast.BlockStatement{
									Meta: ast.New(T, 2, comments(), comments("// Trailing comment")),
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: ast.New(T, 2),
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

	t.Run("if else if else ", func(t *testing.T) {
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
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.IfStatement{
								Meta: ast.New(T, 1, comments("// Leading comment")),
								Condition: &ast.InfixExpression{
									Meta:     ast.New(T, 1),
									Operator: "~",
									Left: &ast.Ident{
										Meta:  ast.New(T, 1),
										Value: "req.http.Host",
									},
									Right: &ast.String{
										Meta:  ast.New(T, 1),
										Value: "example.com",
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: ast.New(T, 2),
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: ast.New(T, 2),
										},
									},
								},
								Another: []*ast.IfStatement{
									{
										Meta: ast.New(T, 1),
										Condition: &ast.InfixExpression{
											Meta:     ast.New(T, 1),
											Operator: "~",
											Left: &ast.Ident{
												Meta:  ast.New(T, 1),
												Value: "req.http.X-Forwarded-For",
											},
											Right: &ast.String{
												Meta:  ast.New(T, 1),
												Value: "192.168.0.1",
											},
										},
										Consequence: &ast.BlockStatement{
											Meta: ast.New(T, 2),
											Statements: []ast.Statement{
												&ast.RestartStatement{
													Meta: ast.New(T, 2),
												},
											},
										},
									},
								},
								Alternative: &ast.BlockStatement{
									Meta: ast.New(T, 2),
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: ast.New(T, 2),
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

	t.Run("if elseif else ", func(t *testing.T) {
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
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.IfStatement{
								Meta: ast.New(T, 1, comments("// Leading comment")),
								Condition: &ast.InfixExpression{
									Meta:     ast.New(T, 1),
									Operator: "~",
									Left: &ast.Ident{
										Meta:  ast.New(T, 1),
										Value: "req.http.Host",
									},
									Right: &ast.String{
										Meta:  ast.New(T, 1),
										Value: "example.com",
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: ast.New(T, 2),
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: ast.New(T, 2),
										},
									},
								},
								Another: []*ast.IfStatement{
									{
										Meta: ast.New(T, 1),
										Condition: &ast.InfixExpression{
											Meta:     ast.New(T, 1),
											Operator: "~",
											Left: &ast.Ident{
												Meta:  ast.New(T, 1),
												Value: "req.http.X-Forwarded-For",
											},
											Right: &ast.String{
												Meta:  ast.New(T, 1),
												Value: "192.168.0.1",
											},
										},
										Consequence: &ast.BlockStatement{
											Meta: ast.New(T, 2),
											Statements: []ast.Statement{
												&ast.RestartStatement{
													Meta: ast.New(T, 2),
												},
											},
										},
									},
								},
								Alternative: &ast.BlockStatement{
									Meta: ast.New(T, 2),
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: ast.New(T, 2),
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
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.IfStatement{
								Meta: ast.New(T, 1, comments("// Leading comment")),
								Condition: &ast.InfixExpression{
									Meta:     ast.New(T, 1),
									Operator: "~",
									Left: &ast.Ident{
										Meta:  ast.New(T, 1),
										Value: "req.http.Host",
									},
									Right: &ast.String{
										Meta:  ast.New(T, 1),
										Value: "example.com",
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: ast.New(T, 2),
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: ast.New(T, 2),
										},
									},
								},
								Another: []*ast.IfStatement{
									{
										Meta: ast.New(T, 1),
										Condition: &ast.InfixExpression{
											Meta:     ast.New(T, 1),
											Operator: "~",
											Left: &ast.Ident{
												Meta:  ast.New(T, 1),
												Value: "req.http.X-Forwarded-For",
											},
											Right: &ast.String{
												Meta:  ast.New(T, 1),
												Value: "192.168.0.1",
											},
										},
										Consequence: &ast.BlockStatement{
											Meta: ast.New(T, 2),
											Statements: []ast.Statement{
												&ast.RestartStatement{
													Meta: ast.New(T, 2),
												},
											},
										},
									},
								},
								Alternative: &ast.BlockStatement{
									Meta: ast.New(T, 2),
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: ast.New(T, 2),
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

	t.Run("Full comments", func(t *testing.T) {
		input := `
sub vcl_recv {
	// If Leading comment
	if (req.http.Host ~ "example.com") {
		restart;
		// If Infix comment
	} // If Trailing comment
	// Elsif Leading comment
	elsif (req.http.X-Forwarded-For ~ "192.168.0.1") {
		restart;
		// Elsif Infix comment
	}
	// Else Leading comment
	else {
		restart;
		// Else Infix comment
	} // Else Trailing comment
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
							&ast.IfStatement{
								Meta: ast.New(T, 1, comments("// If Leading comment")),
								Condition: &ast.InfixExpression{
									Meta: ast.New(T, 1),
									Left: &ast.Ident{
										Meta:  ast.New(T, 1),
										Value: "req.http.Host",
									},
									Operator: "~",
									Right: &ast.String{
										Meta:  ast.New(T, 1),
										Value: "example.com",
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: ast.New(T, 2, ast.Comments{}, comments("// If Trailing comment"), comments("// If Infix comment")),
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: ast.New(T, 2),
										},
									},
								},
								Another: []*ast.IfStatement{
									{
										Meta: ast.New(T, 1, comments("// Elsif Leading comment")),
										Condition: &ast.InfixExpression{
											Meta: ast.New(T, 1),
											Left: &ast.Ident{
												Meta:  ast.New(T, 1),
												Value: "req.http.X-Forwarded-For",
											},
											Operator: "~",
											Right: &ast.String{
												Meta:  ast.New(T, 1),
												Value: "192.168.0.1",
											},
										},
										Consequence: &ast.BlockStatement{
											Meta: ast.New(T, 2, ast.Comments{}, ast.Comments{}, comments("// Elsif Infix comment")),
											Statements: []ast.Statement{
												&ast.RestartStatement{
													Meta: ast.New(T, 2),
												},
											},
										},
									},
								},
								Alternative: &ast.BlockStatement{
									Meta: ast.New(T, 2, ast.Comments{}, comments("// Else Trailing comment"), comments("// Else Infix comment")),
									Statements: []ast.Statement{
										&ast.RestartStatement{
											Meta: ast.New(T, 2),
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
	t.Run("switch statement", func(t *testing.T) {
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
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.SwitchStatement{
								Meta: ast.New(T, 1, comments("// Switch")),
								Control: &ast.Ident{
									Meta:  ast.New(T, 1),
									Value: "req.http.host",
								},
								Default: 1,
								Cases: []*ast.CaseStatement{
									{
										Meta: ast.New(T, 2),
										Test: &ast.InfixExpression{
											Meta:     ast.New(T, 2),
											Operator: "==",
											Right: &ast.String{
												Meta:  ast.New(T, 2),
												Value: "1"},
										},
										Statements: []ast.Statement{
											&ast.EsiStatement{
												Meta: ast.New(T, 2),
											},
											&ast.BreakStatement{
												Meta: ast.New(T, 2),
											},
										},
									},
									{
										Meta: ast.New(T, 2),
										Statements: []ast.Statement{
											&ast.EsiStatement{
												Meta: ast.New(T, 2),
											},
											&ast.FallthroughStatement{
												Meta: ast.New(T, 2),
											},
										},
										Fallthrough: true,
									},
									{
										Meta: ast.New(T, 2),
										Test: &ast.InfixExpression{
											Meta:     ast.New(T, 2),
											Operator: "~",
											Right: &ast.String{
												Meta:  ast.New(T, 2, comments("/* infix */")),
												Value: "[2-3]"},
										},
										Statements: []ast.Statement{
											&ast.EsiStatement{
												Meta: ast.New(T, 2),
											},
											&ast.BreakStatement{
												Meta: ast.New(T, 2),
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
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.SwitchStatement{
								Meta: ast.New(T, 1, comments("// Switch")),
								Control: &ast.FunctionCallExpression{
									Meta: ast.New(T, 1),
									Function: &ast.Ident{
										Meta:  ast.New(T, 1),
										Value: "uuid.version4",
									},
									Arguments: []ast.Expression{},
								},
								Default: -1,
								Cases: []*ast.CaseStatement{
									{
										Meta: ast.New(T, 2),
										Test: &ast.InfixExpression{
											Meta:     ast.New(T, 2),
											Operator: "==",
											Right: &ast.String{
												Meta:  ast.New(T, 2),
												Value: "xxx-xxx-xxx"},
										},
										Statements: []ast.Statement{
											&ast.EsiStatement{
												Meta: ast.New(T, 2),
											},
											&ast.BreakStatement{
												Meta: ast.New(T, 2),
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
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.SwitchStatement{
								Meta: ast.New(T, 1, comments("// Switch")),
								Control: &ast.Boolean{
									Meta:  ast.New(T, 1),
									Value: true,
								},
								Default: 1,
								Cases: []*ast.CaseStatement{
									{
										Meta: ast.New(T, 2),
										Test: &ast.InfixExpression{
											Meta:     ast.New(T, 2),
											Operator: "==",
											Right: &ast.String{
												Meta:  ast.New(T, 2),
												Value: "1"},
										},
										Statements: []ast.Statement{
											&ast.EsiStatement{
												Meta: ast.New(T, 2),
											},
											&ast.BreakStatement{
												Meta: ast.New(T, 2),
											},
										},
									},
									{
										Meta: ast.New(T, 2),
										Statements: []ast.Statement{
											&ast.EsiStatement{
												Meta: ast.New(T, 2),
											},
											&ast.BreakStatement{
												Meta: ast.New(T, 2),
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
	// Switch Leading comment
	switch (req.http.Host) {
	// Case1 Leading comment
	case "1": // Case1 Trailing comment
		esi;
		// Break1 Leading comment
		break; // Break1 Trailing comment
	// Default Leading comment
	default: // Default Trailing comment
		esi;
		break;
	// Switch Infix comment
	} // Switch Trailing comment
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
							&ast.SwitchStatement{
								Meta: ast.New(T, 1, comments("// Switch Leading comment"), comments("// Switch Trailing comment"), comments("// Switch Infix comment")),
								Control: &ast.Ident{
									Meta:  ast.New(T, 1),
									Value: "req.http.Host",
								},
								Default: 1,
								Cases: []*ast.CaseStatement{
									{
										Meta: ast.New(T, 2, comments("// Case1 Leading comment"), comments("// Case1 Trailing comment")),
										Test: &ast.InfixExpression{
											Meta:     ast.New(T, 2),
											Operator: "==",
											Right: &ast.String{
												Meta:  ast.New(T, 2),
												Value: "1",
											},
										},
										Statements: []ast.Statement{
											&ast.EsiStatement{
												Meta: ast.New(T, 2),
											},
											&ast.BreakStatement{
												Meta: ast.New(T, 2, comments("// Break1 Leading comment"), comments("// Break1 Trailing comment")),
											},
										},
									},
									{
										Meta: ast.New(T, 2, comments("// Default Leading comment"), comments("// Default Trailing comment")),
										Statements: []ast.Statement{
											&ast.EsiStatement{
												Meta: ast.New(T, 2),
											},
											&ast.BreakStatement{
												Meta: ast.New(T, 2),
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
	unset req.http.Host; // Trailing comment
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
								Meta:  ast.New(T, 1),
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
	add req.http.Cookie:session = "example.com"; // Trailing comment
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
							&ast.AddStatement{
								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
								Ident: &ast.Ident{
									Meta:  ast.New(T, 1),
									Value: "req.http.Cookie:session",
								},
								Operator: &ast.Operator{
									Meta:     ast.New(T, 1),
									Operator: "=",
								},
								Value: &ast.String{
									Meta:  ast.New(T, 1),
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
					Meta: ast.New(T, 0, comments("// Subroutine")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "vcl_recv",
					},
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 1),
						Statements: []ast.Statement{
							&ast.AddStatement{
								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
								Ident: &ast.Ident{
									Meta:  ast.New(T, 1),
									Value: "req.http.Host",
								},
								Operator: &ast.Operator{
									Meta:     ast.New(T, 1),
									Operator: "=",
								},
								Value: &ast.InfixExpression{
									Meta:     ast.New(T, 1),
									Operator: "+",
									Left: &ast.InfixExpression{
										Meta:     ast.New(T, 1),
										Operator: "+",
										Left: &ast.String{
											Meta:  ast.New(T, 1),
											Value: "example",
										},
										Right: &ast.Ident{
											Meta:  ast.New(T, 1),
											Value: "req.http.User-Agent",
										},
									},
									Right: &ast.String{
										Meta:  ast.New(T, 1),
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
			call feature_mod_recv; // Trailing comment
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
							&ast.CallStatement{
								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
								Subroutine: &ast.Ident{
									Meta:  ast.New(T, 1),
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
			call feature_mod_recv(); // Trailing comment
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
							&ast.CallStatement{
								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
								Subroutine: &ast.Ident{
									Meta:  ast.New(T, 1),
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
	input := `// Subroutine
sub vcl_recv {
	// Leading comment
	declare local var.foo STRING; // Trailing comment
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
						&ast.DeclareStatement{
							Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
							Name: &ast.Ident{
								Meta:  ast.New(T, 1),
								Value: "var.foo",
							},
							ValueType: &ast.Ident{
								Meta:  ast.New(T, 1),
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
}

func TestLogStatement(t *testing.T) {
	input := `// Subroutine
sub vcl_recv {
	// Leading comment
	log {"syslog "}
		{" fastly-log :: "} {"	timestamp:"}
		req.http.Timestamp
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
								Meta:     ast.New(T, 1),
								Operator: "+",
								Right: &ast.Ident{
									Meta:  ast.New(T, 1),
									Value: "req.http.Timestamp",
								},
								Left: &ast.InfixExpression{
									Meta:     ast.New(T, 1),
									Operator: "+",
									Right: &ast.String{
										Meta: ast.New(T, 1),
										Value: "	timestamp:",
									},
									Left: &ast.InfixExpression{
										Meta:     ast.New(T, 1),
										Operator: "+",
										Right: &ast.String{
											Meta:  ast.New(T, 1),
											Value: " fastly-log :: ",
										},
										Left: &ast.String{
											Meta:  ast.New(T, 1),
											Value: "syslog ",
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
	input := `// Subroutine
sub vcl_recv {
	// Leading comment
	return(deliver); // Trailing comment
}`
	var rt ast.Expression
	rt = &ast.Ident{
		Meta:  ast.New(T, 1),
		Value: "deliver",
	}
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
							Meta:             ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
							ReturnExpression: &rt,
							HasParenthesis:   true,
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

func TestSyntheticStatement(t *testing.T) {
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
									Meta:  ast.New(T, 1),
									Value: "Access ",
								},
								Operator: "+",
								Right: &ast.String{
									Meta:  ast.New(T, 1),
									Value: "denied",
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

func TestSyntheticBase64Statement(t *testing.T) {
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
									Meta:  ast.New(T, 1),
									Value: "Access ",
								},
								Operator: "+",
								Right: &ast.String{
									Meta:  ast.New(T, 1),
									Value: "denied",
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
}
