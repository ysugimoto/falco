package parser

import (
	"testing"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/token"
)

func TestParseIfExpression(t *testing.T) {
	input := `// Subroutine
sub vcl_recv {
	// Leading comment
	set req.http.Foo = if (req.http.Host, "example.com", "foobar"); // Trailing comment
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
						&ast.SetStatement{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.SET,
									Literal:  "set",
									Line:     4,
									Position: 2,
								},
								Leading:            comments("// Leading comment"),
								Trailing:           comments("// Trailing comment"),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            4,
								EndPosition:        63,
							},
							Ident: &ast.Ident{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.IDENT,
										Literal:  "req.http.Foo",
										Line:     4,
										Position: 6,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            4,
									EndPosition:        17,
								},
								Value: "req.http.Foo",
							},
							Operator: &ast.Operator{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.ASSIGN,
										Literal:  "=",
										Line:     4,
										Position: 19,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            4,
									EndPosition:        19,
								},
								Operator: "=",
							},
							Value: &ast.IfExpression{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.IF,
										Literal:  "if",
										Line:     4,
										Position: 21,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            4,
									EndPosition:        63,
								},
								Condition: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.Host",
											Line:     4,
											Position: 25,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        37,
									},
									Value: "req.http.Host",
								},
								Consequence: &ast.String{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.STRING,
											Literal:  "example.com",
											Line:     4,
											Position: 40,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        52,
									},
									Value: "example.com",
								},
								Alternative: &ast.String{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.STRING,
											Literal:  "foobar",
											Line:     4,
											Position: 55,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        62,
									},
									Value: "foobar",
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

func TestParseInfixIfExpression(t *testing.T) {
	input := `// Subroutine
sub vcl_recv {
	// Leading comment
	log {"foo bar"}
		if (req.http.Host, "example.com", "foobar")
		{"baz"}; // Trailing comment
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
						&ast.LogStatement{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.LOG,
									Literal:  "log",
									Line:     4,
									Position: 2,
								},
								Leading:            comments("// Leading comment"),
								Trailing:           comments("// Trailing comment"),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            6,
								EndPosition:        9,
							},
							Value: &ast.InfixExpression{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "foo bar",
										Line:     4,
										Position: 6,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            6,
									EndPosition:        9,
								},
								Operator: "+",
								Left: &ast.InfixExpression{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.STRING,
											Literal:  "foo bar",
											Line:     4,
											Position: 6,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            5,
										EndPosition:        45,
									},
									Operator: "+",
									Left: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "foo bar",
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
										Value:      "foo bar",
										LongString: true,
									},
									Right: &ast.IfExpression{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IF,
												Literal:  "if",
												Line:     5,
												Position: 3,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            5,
											EndPosition:        45,
										},
										Condition: &ast.Ident{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.IDENT,
													Literal:  "req.http.Host",
													Line:     5,
													Position: 7,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            5,
												EndPosition:        19,
											},
											Value: "req.http.Host",
										},
										Consequence: &ast.String{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.STRING,
													Literal:  "example.com",
													Line:     5,
													Position: 22,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            5,
												EndPosition:        34,
											},
											Value: "example.com",
										},
										Alternative: &ast.String{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.STRING,
													Literal:  "foobar",
													Line:     5,
													Position: 37,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            5,
												EndPosition:        44,
											},
											Value: "foobar",
										},
									},
								},
								Right: &ast.String{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.STRING,
											Literal:  "baz",
											Line:     6,
											Position: 3,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            6,
										EndPosition:        9,
									},
									Value:      "baz",
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
}

func TestParseFunctionCallExpression(t *testing.T) {
	t.Run("no argument", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	set req.http.X-Trace-Id = uuid.version4();
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
									EndPosition:        42,
								},
								Ident: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.X-Trace-Id",
											Line:     3,
											Position: 6,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            3,
										EndPosition:        24,
									},
									Value: "req.http.X-Trace-Id",
								},
								Operator: &ast.Operator{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.ASSIGN,
											Literal:  "=",
											Line:     3,
											Position: 26,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            3,
										EndPosition:        26,
									},
									Operator: "=",
								},
								Value: &ast.FunctionCallExpression{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "uuid.version4",
											Line:     3,
											Position: 28,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            3,
										EndPosition:        42,
									},
									Function: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "uuid.version4",
												Line:     3,
												Position: 28,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            3,
											EndPosition:        40,
										},
										Value: "uuid.version4",
									},
									Arguments: []ast.Expression{},
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

	t.Run("some arguments", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	set req.http.X-Trace-Id = regsub(req.http.Host, "example.com", "");
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
									EndPosition:        67,
								},
								Ident: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.X-Trace-Id",
											Line:     3,
											Position: 6,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            3,
										EndPosition:        24,
									},
									Value: "req.http.X-Trace-Id",
								},
								Operator: &ast.Operator{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.ASSIGN,
											Literal:  "=",
											Line:     3,
											Position: 26,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            3,
										EndPosition:        26,
									},
									Operator: "=",
								},
								Value: &ast.FunctionCallExpression{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "regsub",
											Line:     3,
											Position: 28,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            3,
										EndPosition:        67,
									},
									Function: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "regsub",
												Line:     3,
												Position: 28,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            3,
											EndPosition:        33,
										},
										Value: "regsub",
									},
									Arguments: []ast.Expression{
										&ast.Ident{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.IDENT,
													Literal:  "req.http.Host",
													Line:     3,
													Position: 35,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            3,
												EndPosition:        47,
											},
											Value: "req.http.Host",
										},
										&ast.String{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.STRING,
													Literal:  "example.com",
													Line:     3,
													Position: 50,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            3,
												EndPosition:        62,
											},
											Value: "example.com",
										},
										&ast.String{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.STRING,
													Literal:  "",
													Line:     3,
													Position: 65,
												},
												Leading:            comments(),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               1,
												PreviousEmptyLines: 0,
												EndLine:            3,
												EndPosition:        66,
											},
											Value: "",
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

func TestParseInfixExpression(t *testing.T) {
	t.Run("having infix comments in if condition", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// foo
	if (req.http.Foo && /* comment */ req.http.Bar) {
		// foo
		set req.http.Result = req.http.Foo req.http.Bar;
	}
	// end
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
							Infix:              comments("// end"),
							Nest:               1,
							PreviousEmptyLines: 0,
							EndLine:            9,
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
									Leading:            comments("// foo"),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            7,
									EndPosition:        2,
								},
								Keyword: "if",
								Condition: &ast.InfixExpression{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.Foo",
											Line:     4,
											Position: 6,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               1,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        47,
									},
									Operator: "&&",
									Left: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.Foo",
												Line:     4,
												Position: 6,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        17,
										},
										Value: "req.http.Foo",
									},
									Right: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.Bar",
												Line:     4,
												Position: 36,
											},
											Leading:            comments("/* comment */"),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               1,
											PreviousEmptyLines: 0,
											EndLine:            4,
											EndPosition:        47,
										},
										Value: "req.http.Bar",
									},
								},
								Consequence: &ast.BlockStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.LEFT_BRACE,
											Literal:  "{",
											Line:     4,
											Position: 50,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            7,
										EndPosition:        2,
									},
									Statements: []ast.Statement{
										&ast.SetStatement{
											Meta: &ast.Meta{
												Token: token.Token{
													Type:     token.SET,
													Literal:  "set",
													Line:     6,
													Position: 3,
												},
												Leading:            comments("// foo"),
												Trailing:           comments(),
												Infix:              comments(),
												Nest:               2,
												PreviousEmptyLines: 0,
												EndLine:            6,
												EndPosition:        49,
											},
											Operator: &ast.Operator{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.ASSIGN,
														Literal:  "=",
														Line:     6,
														Position: 23,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            6,
													EndPosition:        23,
												},
												Operator: "=",
											},
											Ident: &ast.Ident{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.IDENT,
														Literal:  "req.http.Result",
														Line:     6,
														Position: 7,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            6,
													EndPosition:        21,
												},
												Value: "req.http.Result",
											},
											Value: &ast.InfixExpression{
												Meta: &ast.Meta{
													Token: token.Token{
														Type:     token.IDENT,
														Literal:  "req.http.Foo",
														Line:     6,
														Position: 25,
													},
													Leading:            comments(),
													Trailing:           comments(),
													Infix:              comments(),
													Nest:               2,
													PreviousEmptyLines: 0,
													EndLine:            6,
													EndPosition:        49,
												},
												Operator: "+",
												Left: &ast.Ident{
													Meta: &ast.Meta{
														Token: token.Token{
															Type:     token.IDENT,
															Literal:  "req.http.Foo",
															Line:     6,
															Position: 25,
														},
														Leading:            comments(),
														Trailing:           comments(),
														Infix:              comments(),
														Nest:               2,
														PreviousEmptyLines: 0,
														EndLine:            6,
														EndPosition:        36,
													},
													Value: "req.http.Foo",
												},
												Right: &ast.Ident{
													Meta: &ast.Meta{
														Token: token.Token{
															Type:     token.IDENT,
															Literal:  "req.http.Bar",
															Line:     6,
															Position: 38,
														},
														Leading:            comments(),
														Trailing:           comments(),
														Infix:              comments(),
														Nest:               2,
														PreviousEmptyLines: 0,
														EndLine:            6,
														EndPosition:        49,
													},
													Value: "req.http.Bar",
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
