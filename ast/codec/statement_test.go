package codec

import (
	"testing"

	"github.com/ysugimoto/falco/ast"
)

type statementTest struct {
	name   string
	input  string
	expect ast.Statement
}

func TestAddStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic add statement",
			input: `
sub vcl_deliver {
	add resp.http.Set-Cookie = "foo=bar";
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_deliver"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.AddStatement{
							Ident: &ast.Ident{Value: "resp.http.Set-Cookie"},
							Operator: &ast.Operator{
								Operator: "=",
							},
							Value: &ast.String{Value: "foo=bar"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestBlockStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic block statement",
			input: `
sub vcl_recv {
	{
		declare local var.V STRING;
	}
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_recv"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.BlockStatement{
							Statements: []ast.Statement{
								&ast.DeclareStatement{
									Name:      &ast.Ident{Value: "var.V"},
									ValueType: &ast.Ident{Value: "STRING"},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestCallStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic call statement",
			input: `
sub vcl_recv {
	call some_function;
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_recv"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.CallStatement{
							Subroutine: &ast.Ident{Value: "some_function"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestDeclareStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic declare statement",
			input: `
sub vcl_recv {
	call some_function;
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_recv"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.CallStatement{
							Subroutine: &ast.Ident{Value: "some_function"},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestErrorStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic error statement",
			input: `
sub vcl_recv {
	error 500;
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_recv"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.ErrorStatement{
							Code: &ast.Integer{Value: 500},
						},
					},
				},
			},
		},
		{
			name: "with response expression",
			input: `
sub vcl_recv {
	error 500 "error";
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_recv"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.ErrorStatement{
							Code:     &ast.Integer{Value: 500},
							Argument: &ast.String{Value: "error"},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestEsiStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic esi statement",
			input: `
sub vcl_fetch {
	esi;
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_fetch"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.EsiStatement{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestFunctionCallStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "function call without argument",
			input: `
sub vcl_fetch {
	h3.alt_svc();
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_fetch"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.FunctionCallStatement{
							Function: &ast.Ident{Value: "h3.alt_svc"},
						},
					},
				},
			},
		},
		{
			name: "function call with arguments",
			input: `
sub vcl_fetch {
	std.collect(req.http.Cookie, ";");
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_fetch"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.FunctionCallStatement{
							Function: &ast.Ident{Value: "std.collect"},
							Arguments: []ast.Expression{
								&ast.Ident{Value: "req.http.Cookie"},
								&ast.String{Value: ";"},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestGotoStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic goto statement",
			input: `
sub vcl_fetch {
	goto FOO;
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_fetch"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.GotoStatement{
							Destination: &ast.Ident{Value: "FOO"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestGotoDestinationStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic goto destination statement",
			input: `
sub vcl_fetch {
	FOO:
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_fetch"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.GotoDestinationStatement{
							Name: &ast.Ident{Value: "FOO:"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestIfStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic if statement",
			input: `
sub vcl_fetch {
	if (req.http.Host == "example.com") {
		restart;
	}
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_fetch"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.IfStatement{
							Keyword: "if",
							Condition: &ast.InfixExpression{
								Left:     &ast.Ident{Value: "req.http.Host"},
								Operator: "==",
								Right:    &ast.String{Value: "example.com"},
							},
							Another: []*ast.IfStatement{},
							Consequence: &ast.BlockStatement{
								Statements: []ast.Statement{
									&ast.RestartStatement{},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "if-else statement",
			input: `
sub vcl_fetch {
	if (req.http.Host == "example.com") {
		restart;
	} else {
		set req.http.Host = "example.jp";
	}
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_fetch"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.IfStatement{
							Keyword: "if",
							Condition: &ast.InfixExpression{
								Left:     &ast.Ident{Value: "req.http.Host"},
								Operator: "==",
								Right:    &ast.String{Value: "example.com"},
							},
							Consequence: &ast.BlockStatement{
								Statements: []ast.Statement{
									&ast.RestartStatement{},
								},
							},
							Another: []*ast.IfStatement{},
							Alternative: &ast.ElseStatement{
								Consequence: &ast.BlockStatement{
									Statements: []ast.Statement{
										&ast.SetStatement{
											Ident: &ast.Ident{Value: "req.http.Host"},
											Operator: &ast.Operator{
												Operator: "=",
											},
											Value: &ast.String{Value: "example.jp"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "if-elseif-else statement",
			input: `
sub vcl_fetch {
	if (req.http.Host == "example.com") {
		restart;
	} else if (req.http.Host == "another.example.com") {
		restart;
	} else {
		set req.http.Host = "example.jp";
	}
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_fetch"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.IfStatement{
							Keyword: "if",
							Condition: &ast.InfixExpression{
								Left:     &ast.Ident{Value: "req.http.Host"},
								Operator: "==",
								Right:    &ast.String{Value: "example.com"},
							},
							Consequence: &ast.BlockStatement{
								Statements: []ast.Statement{
									&ast.RestartStatement{},
								},
							},
							Another: []*ast.IfStatement{
								{
									Keyword: "else if",
									Condition: &ast.InfixExpression{
										Left:     &ast.Ident{Value: "req.http.Host"},
										Operator: "==",
										Right:    &ast.String{Value: "another.example.com"},
									},
									Another: []*ast.IfStatement{},
									Consequence: &ast.BlockStatement{
										Statements: []ast.Statement{
											&ast.RestartStatement{},
										},
									},
								},
							},
							Alternative: &ast.ElseStatement{
								Consequence: &ast.BlockStatement{
									Statements: []ast.Statement{
										&ast.SetStatement{
											Ident: &ast.Ident{Value: "req.http.Host"},
											Operator: &ast.Operator{
												Operator: "=",
											},
											Value: &ast.String{Value: "example.jp"},
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestImportStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic import statement",
			input: `
import boltsort;
`,
			expect: &ast.ImportStatement{
				Name: &ast.Ident{Value: "boltsort"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestIncludeStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic include statement",
			input: `
include "another_vcl";
`,
			expect: &ast.IncludeStatement{
				Module: &ast.String{Value: "another_vcl"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestLogStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic log statement",
			input: `
sub vcl_fetch {
	log req.http.Foo {" and "} req.backend;
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_fetch"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.LogStatement{
							Value: &ast.InfixExpression{
								Left: &ast.InfixExpression{
									Left:     &ast.Ident{Value: "req.http.Foo"},
									Operator: "+",
									Right:    &ast.String{Value: " and "},
								},
								Operator: "+",
								Right:    &ast.Ident{Value: "req.backend"},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestRemoveStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic remove statement",
			input: `
sub vcl_fetch {
	remove req.http.Foo;
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_fetch"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.RemoveStatement{
							Ident: &ast.Ident{Value: "req.http.Foo"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestRestartStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic restart statement",
			input: `
sub vcl_fetch {
	restart;
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_fetch"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.RestartStatement{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestReturnStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic return statement",
			input: `
sub vcl_fetch {
	return deliver;
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_fetch"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.ReturnStatement{
							ReturnExpression: &ast.Ident{Value: "deliver"},
						},
					},
				},
			},
		},
		{
			name: "basic return statement with parenthesis",
			input: `
sub vcl_fetch {
	return(deliver);
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_fetch"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.ReturnStatement{
							ReturnExpression: &ast.Ident{Value: "deliver"},
							HasParenthesis:   true,
						},
					},
				},
			},
		},
		{
			name: "basic return statement without expression",
			input: `
sub vcl_fetch {
	return;
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_fetch"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.ReturnStatement{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestSetStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic set statement",
			input: `
sub vcl_deliver {
	set resp.http.Foo = "bar" req.backend;
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_deliver"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.SetStatement{
							Ident: &ast.Ident{Value: "resp.http.Foo"},
							Operator: &ast.Operator{
								Operator: "=",
							},
							Value: &ast.InfixExpression{
								Left:     &ast.String{Value: "bar"},
								Operator: "+",
								Right:    &ast.Ident{Value: "req.backend"},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestSwitchStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic switch statement",
			input: `
sub vcl_deliver {
	switch (req.http.Host) {
	case "example.com":
		set req.http.Foo = "com";
		break;
	case "example.jp":
		set req.http.Foo = "jp";
		fallthrough;
	default:
		set req.http.Foo = "unknown";
		break;
	}
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_deliver"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.SwitchStatement{
							Control: &ast.SwitchControl{
								Expression: &ast.Ident{Value: "req.http.Host"},
							},
							Cases: []*ast.CaseStatement{
								{
									Test: &ast.InfixExpression{
										Operator: "==",
										Right:    &ast.String{Value: "example.com"},
									},
									Statements: []ast.Statement{
										&ast.SetStatement{
											Ident: &ast.Ident{Value: "req.http.Foo"},
											Operator: &ast.Operator{
												Operator: "=",
											},
											Value: &ast.String{Value: "com"},
										},
										&ast.BreakStatement{},
									},
								},
								{
									Test: &ast.InfixExpression{
										Operator: "==",
										Right:    &ast.String{Value: "example.jp"},
									},
									Statements: []ast.Statement{
										&ast.SetStatement{
											Ident: &ast.Ident{Value: "req.http.Foo"},
											Operator: &ast.Operator{
												Operator: "=",
											},
											Value: &ast.String{Value: "jp"},
										},
										&ast.FallthroughStatement{},
									},
									Fallthrough: true,
								},
								{
									Statements: []ast.Statement{
										&ast.SetStatement{
											Ident: &ast.Ident{Value: "req.http.Foo"},
											Operator: &ast.Operator{
												Operator: "=",
											},
											Value: &ast.String{Value: "unknown"},
										},
										&ast.BreakStatement{},
									},
								},
							},
							Default: 2,
						},
					},
				},
			},
		},
		{
			name: "switch statement without default",
			input: `
sub vcl_deliver {
	switch (req.http.Host) {
	case "example.com":
		set req.http.Foo = "com";
		fallthrough;
	case "example.jp":
		set req.http.Foo = "jp";
		break;
	}
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_deliver"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.SwitchStatement{
							Control: &ast.SwitchControl{
								Expression: &ast.Ident{Value: "req.http.Host"},
							},
							Cases: []*ast.CaseStatement{
								{
									Test: &ast.InfixExpression{
										Operator: "==",
										Right:    &ast.String{Value: "example.com"},
									},
									Statements: []ast.Statement{
										&ast.SetStatement{
											Ident: &ast.Ident{Value: "req.http.Foo"},
											Operator: &ast.Operator{
												Operator: "=",
											},
											Value: &ast.String{Value: "com"},
										},
										&ast.FallthroughStatement{},
									},
									Fallthrough: true,
								},
								{
									Test: &ast.InfixExpression{
										Operator: "==",
										Right:    &ast.String{Value: "example.jp"},
									},
									Statements: []ast.Statement{
										&ast.SetStatement{
											Ident: &ast.Ident{Value: "req.http.Foo"},
											Operator: &ast.Operator{
												Operator: "=",
											},
											Value: &ast.String{Value: "jp"},
										},
										&ast.BreakStatement{},
									},
								},
							},
							Default: -1,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestSyntheticStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic synthetic statement",
			input: `
sub vcl_error {
	synthetic req.http.Foo {" and "} req.backend;
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_error"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.SyntheticStatement{
							Value: &ast.InfixExpression{
								Left: &ast.InfixExpression{
									Left:     &ast.Ident{Value: "req.http.Foo"},
									Operator: "+",
									Right:    &ast.String{Value: " and "},
								},
								Operator: "+",
								Right:    &ast.Ident{Value: "req.backend"},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestSyntheticBase64Statement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic synthetic.base64 statement",
			input: `
sub vcl_error {
	synthetic.base64 "RmFzdGx5IGlzIGZhbnRhc3RpYyBDRE4h";
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_error"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.SyntheticBase64Statement{
							Value: &ast.String{Value: "RmFzdGx5IGlzIGZhbnRhc3RpYyBDRE4h"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}

func TestUnsetStatement(t *testing.T) {
	tests := []statementTest{
		{
			name: "basic unset statement",
			input: `
sub vcl_fetch {
	unset req.http.Foo;
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_fetch"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.UnsetStatement{
							Ident: &ast.Ident{Value: "req.http.Foo"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatement(t, tt.input, tt.expect)
		})
	}
}
