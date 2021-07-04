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
		cmpopts.IgnoreFields(ast.Operator{}, "Token"),

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

func TestDirectorParse(t *testing.T) {
	input := `
backend foo {
	.host = "example.com";
}

director bar client {
	.quorum  = 50%;
	{ .backend = foo; .weight = 1; }
}`
	_, err := New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Errorf("%+v", err)
	}
}

func TestIfElseParse(t *testing.T) {
	input := `
sub foo {
	if (req.http.Host) {
		restart;
	} else if (req.http.X-Forwarded-For) {
		error 602;
	} else {
		error 601;
	}
}`
	_, err := New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Errorf("%+v", err)
	}
}

func TestSubroutineComment(t *testing.T) {
	input := `
sub vcl_recv {
	# FASTLY recv
	set req.http.Host = "example.com";
}`
	_, err := New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Errorf("%+v", err)
	}
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

func TestParseACL(t *testing.T) {
	input := `// Acl definition
acl internal {
	"192.168.0.1";
	"192.168.0.2"/32;
	!"192.168.0.3";
	!"192.168.0.4"/32;
	// Leading comment
	"192.168.0.5"; // Trailing comment
}`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.AclDeclaration{
				Meta: ast.New(T, 0, comments("// Acl definition")),
				Name: &ast.Ident{
					Meta:  ast.New(token.Token{}, 0),
					Value: "internal",
				},
				CIDRs: []*ast.AclCidr{
					{
						Meta: ast.New(token.Token{}, 1),
						IP: &ast.IP{
							Meta:  ast.New(token.Token{}, 0),
							Value: "192.168.0.1",
						},
					},
					{
						Meta: ast.New(token.Token{}, 1),
						IP: &ast.IP{
							Meta:  ast.New(token.Token{}, 0),
							Value: "192.168.0.2",
						},
						Mask: &ast.Integer{
							Meta:  ast.New(token.Token{}, 0),
							Value: 32,
						},
					},
					{
						Meta: ast.New(token.Token{}, 1),
						Inverse: &ast.Boolean{
							Meta:  ast.New(token.Token{}, 0),
							Value: true,
						},
						IP: &ast.IP{
							Meta:  ast.New(token.Token{}, 0),
							Value: "192.168.0.3",
						},
					},
					{
						Meta: ast.New(token.Token{}, 1),
						Inverse: &ast.Boolean{
							Meta:  ast.New(token.Token{}, 0),
							Value: true,
						},
						IP: &ast.IP{
							Meta:  ast.New(token.Token{}, 0),
							Value: "192.168.0.4",
						},
						Mask: &ast.Integer{
							Meta:  ast.New(token.Token{}, 0),
							Value: 32,
						},
					},
					{
						Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
						IP: &ast.IP{
							Meta:  ast.New(token.Token{}, 0),
							Value: "192.168.0.5",
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

func TestParseImport(t *testing.T) {
	input := `// Leading comment
import boltsort; // Trailing comment`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.ImportStatement{
				Meta: ast.New(T, 0, comments("// Leading comment"), comments("// Trailing comment")),
				Name: &ast.Ident{
					Meta:  ast.New(token.Token{}, 0),
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
}

func TestParseBackend(t *testing.T) {
	input := `// Leading comment
backend example {
	// Leading comment
	.host = "example.com"; // Trailing comment
	.probe = {
		// Leading comment
		.request = "GET / HTTP/1.1"; // Trailing comment
	}
}`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.BackendDeclaration{
				Meta: ast.New(T, 0, comments("// Leading comment")),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "example",
				},
				Properties: []*ast.BackendProperty{
					{
						Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
						Key: &ast.Ident{
							Meta:  ast.New(T, 0),
							Value: "host",
						},
						Value: &ast.String{
							Meta:  ast.New(T, 0),
							Value: "example.com",
						},
					},
					{
						Meta: ast.New(T, 1),
						Key: &ast.Ident{
							Meta:  ast.New(T, 0),
							Value: "probe",
						},
						Value: &ast.BackendProbeObject{
							Meta: ast.New(T, 1),
							Values: []*ast.BackendProperty{
								{
									Meta: ast.New(T, 2, comments("// Leading comment"), comments("// Trailing comment")),
									Key: &ast.Ident{
										Meta:  ast.New(T, 0),
										Value: "request",
									},
									Value: &ast.String{
										Meta:  ast.New(T, 0),
										Value: "GET / HTTP/1.1",
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

func TestParseTable(t *testing.T) {
	input := `// Table definition
table tbl {
	"foo": "bar",
	// Leading comment
	"lorem": "ipsum", // Trailing comment
	// Leading comment
	"dolor": "sit" // Trailing comment
}`

	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.TableDeclaration{
				Meta: ast.New(T, 0, comments("// Table definition")),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "tbl",
				},
				Properties: []*ast.TableProperty{
					{
						Meta: ast.New(T, 1),
						Key: &ast.String{
							Meta:  ast.New(T, 0),
							Value: "foo",
						},
						Value: &ast.String{
							Meta:  ast.New(T, 0),
							Value: "bar",
						},
					},
					{
						Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
						Key: &ast.String{
							Meta:  ast.New(T, 0),
							Value: "lorem",
						},
						Value: &ast.String{
							Meta:  ast.New(T, 0),
							Value: "ipsum",
						},
					},
					{
						Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
						Key: &ast.String{
							Meta:  ast.New(T, 0),
							Value: "dolor",
						},
						Value: &ast.String{
							Meta:  ast.New(T, 0),
							Value: "sit",
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

func TestParseDirector(t *testing.T) {
	input := `// Director definition
director example client {
	// Leading comment
	.quorum = 20%; // Trailing comment
	// Leading comment
	{ .backend = example; .weight = 1; } // Trailing comment
}`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.DirectorDeclaration{
				Meta: ast.New(T, 0, comments("// Director definition")),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "example",
				},
				DirectorType: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "client",
				},
				Properties: []ast.Expression{
					&ast.DirectorProperty{
						Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
						Key: &ast.Ident{
							Meta:  ast.New(T, 0),
							Value: "quorum",
						},
						Value: &ast.String{
							Meta:  ast.New(T, 0),
							Value: "20%",
						},
					},
					&ast.DirectorBackendObject{
						Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
						Values: []*ast.DirectorProperty{
							&ast.DirectorProperty{
								Meta: ast.New(T, 1),
								Key: &ast.Ident{
									Meta:  ast.New(T, 0),
									Value: "backend",
								},
								Value: &ast.Ident{
									Meta:  ast.New(T, 0),
									Value: "example",
								},
							},
							&ast.DirectorProperty{
								Meta: ast.New(T, 1),
								Key: &ast.Ident{
									Meta:  ast.New(T, 0),
									Value: "weight",
								},
								Value: &ast.Integer{
									Meta:  ast.New(T, 0),
									Value: 1,
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
		t.Errorf("%+v\n", err)
	}
	assert(t, vcl, expect)
}

func TestParseSetStatement(t *testing.T) {
	t.Run("simple assign", func(t *testing.T) {
		input := `// Subroutine
sub vcl_recv {
	// Leading comment
	set /* Host */ req.http.Host = "example.com"; // Trailing comment
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
									Meta:  ast.New(T, 0, comments("/* Host */")),
									Value: "req.http.Host",
								},
								Operator: &ast.Operator{
									Operator: "=",
								},
								Value: &ast.String{
									Meta:  ast.New(T, 0),
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
									Meta:  ast.New(T, 0, comments("/* Host */")),
									Value: "req.http.Host",
								},
								Operator: &ast.Operator{
									Operator: "=",
								},
								Value: &ast.InfixExpression{
									Meta:     ast.New(T, 0),
									Operator: "+",
									Left: &ast.InfixExpression{
										Meta:     ast.New(T, 0),
										Operator: "+",
										Left: &ast.String{
											Meta:  ast.New(T, 0),
											Value: "example.",
										},
										Right: &ast.Ident{
											Meta:  ast.New(T, 0),
											Value: "req.http.User-Agent",
										},
									},
									Right: &ast.String{
										Meta:  ast.New(T, 0),
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
								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
								Condition: &ast.InfixExpression{
									Meta:     ast.New(T, 0),
									Operator: "~",
									Left: &ast.Ident{
										Meta:  ast.New(T, 0),
										Value: "req.http.Host",
									},
									Right: &ast.String{
										Meta:  ast.New(T, 0, comments("/* infix */")),
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
	//
	// 	t.Run("logical and condtions", func(t *testing.T) {
	// 		input := `// Subroutine
	// sub vcl_recv {
	// 	// Leading comment
	// 	if (req.http.Host ~ "example.com" && /* infix */req.http.Host == "foobar") {
	// 		restart;
	// 	} // Trailing comment
	// }`
	// 		expect := &ast.VCL{
	// 			Statements: []ast.Statement{
	// 				&ast.SubroutineDeclaration{
	// 					Meta: ast.New(T, 0, comments("// Subroutine")),
	// 					Name: &ast.Ident{
	// 						Meta:  ast.New(T, 0),
	// 						Value: "vcl_recv",
	// 					},
	// 					Block: &ast.BlockStatement{
	// 						Meta: ast.New(T, 1),
	// 						Statements: []ast.Statement{
	// 							&ast.IfStatement{
	// 								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
	// 								Condition: &ast.InfixExpression{
	// 									Meta:     ast.New(T, 0),
	// 									Operator: "&&",
	// 									Left: &ast.InfixExpression{
	// 										Meta:     ast.New(T, 0),
	// 										Operator: "~",
	// 										Left: &ast.Ident{
	// 											Meta:  ast.New(T, 0),
	// 											Value: "req.http.Host",
	// 										},
	// 										Right: &ast.String{
	// 											Meta:  ast.New(T, 0),
	// 											Value: "example.com",
	// 										},
	// 									},
	// 									Right: &ast.InfixExpression{
	// 										Meta:     ast.New(T, 0),
	// 										Operator: "==",
	// 										Left: &ast.Ident{
	// 											Meta:  ast.New(T, 0, comments("/* infix */")),
	// 											Value: "req.http.Host",
	// 										},
	// 										Right: &ast.String{
	// 											Meta:  ast.New(T, 0),
	// 											Value: "foobar",
	// 										},
	// 									},
	// 								},
	// 								Consequence: &ast.BlockStatement{
	// 									Meta: ast.New(T, 2),
	// 									Statements: []ast.Statement{
	// 										&ast.RestartStatement{
	// 											Meta: ast.New(T, 2),
	// 										},
	// 									},
	// 								},
	// 							},
	// 						},
	// 					},
	// 				},
	// 			},
	// 		}
	// 		vcl, err := New(lexer.NewFromString(input)).ParseVCL()
	// 		if err != nil {
	// 			t.Errorf("%+v", err)
	// 		}
	// 		assert(t, vcl, expect)
	// 	})
	//
	// 	t.Run("logical or condtions", func(t *testing.T) {
	// 		input := `// Subroutine
	// sub vcl_recv {
	// 	// Leading comment
	// 	if (req.http.Host ~ "example.com"/* infix */ || req.http.Host == "foobar") {
	// 		restart;
	// 	}
	// }`
	// 		expect := &ast.VCL{
	// 			Statements: []ast.Statement{
	// 				&ast.SubroutineDeclaration{
	// 					Meta: ast.New(T, 0, comments("// Subroutine")),
	// 					Name: &ast.Ident{
	// 						Meta:  ast.New(T, 0),
	// 						Value: "vcl_recv",
	// 					},
	// 					Block: &ast.BlockStatement{
	// 						Meta: ast.New(T, 1),
	// 						Statements: []ast.Statement{
	// 							&ast.IfStatement{
	// 								Meta: ast.New(T, 1, comments("// Leading comment")),
	// 								Condition: &ast.InfixExpression{
	// 									Meta:     ast.New(T, 0),
	// 									Operator: "||",
	// 									Left: &ast.InfixExpression{
	// 										Meta:     ast.New(T, 0),
	// 										Operator: "~",
	// 										Left: &ast.Ident{
	// 											Meta:  ast.New(T, 0),
	// 											Value: "req.http.Host",
	// 										},
	// 										Right: &ast.String{
	// 											Meta:  ast.New(T, 0, comments(), comments("/* infix */")),
	// 											Value: "example.com",
	// 										},
	// 									},
	// 									Right: &ast.InfixExpression{
	// 										Meta:     ast.New(T, 0),
	// 										Operator: "==",
	// 										Left: &ast.Ident{
	// 											Meta:  ast.New(T, 0),
	// 											Value: "req.http.Host",
	// 										},
	// 										Right: &ast.String{
	// 											Meta:  ast.New(T, 0),
	// 											Value: "foobar",
	// 										},
	// 									},
	// 								},
	// 								Consequence: &ast.BlockStatement{
	// 									Meta: ast.New(T, 2),
	// 									Statements: []ast.Statement{
	// 										&ast.RestartStatement{
	// 											Meta: ast.New(T, 2),
	// 										},
	// 									},
	// 								},
	// 							},
	// 						},
	// 					},
	// 				},
	// 			},
	// 		}
	// 		vcl, err := New(lexer.NewFromString(input)).ParseVCL()
	// 		if err != nil {
	// 			t.Errorf("%+v", err)
	// 		}
	// 		assert(t, vcl, expect)
	// 	})
	//
	// 	t.Run("if-else", func(t *testing.T) {
	// 		input := `// Subroutine
	// sub vcl_recv {
	// 	// Leading comment
	// 	if (req.http.Host ~ "example.com") {
	// 		restart;
	// 	}
	// 	// Leading comment
	// 	else {
	// 		restart;
	// 	} // Trailing comment
	// }`
	// 		expect := &ast.VCL{
	// 			Statements: []ast.Statement{
	// 				&ast.SubroutineDeclaration{
	// 					Meta: ast.New(T, 0, comments("// Subroutine")),
	// 					Name: &ast.Ident{
	// 						Meta:  ast.New(T, 0),
	// 						Value: "vcl_recv",
	// 					},
	// 					Block: &ast.BlockStatement{
	// 						Meta: ast.New(T, 1),
	// 						Statements: []ast.Statement{
	// 							&ast.IfStatement{
	// 								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
	// 								Condition: &ast.InfixExpression{
	// 									Meta:     ast.New(T, 0),
	// 									Operator: "~",
	// 									Left: &ast.Ident{
	// 										Meta:  ast.New(T, 0),
	// 										Value: "req.http.Host",
	// 									},
	// 									Right: &ast.String{
	// 										Meta:  ast.New(T, 0),
	// 										Value: "example.com",
	// 									},
	// 								},
	// 								Consequence: &ast.BlockStatement{
	// 									Meta: ast.New(T, 2),
	// 									Statements: []ast.Statement{
	// 										&ast.RestartStatement{
	// 											Meta: ast.New(T, 2),
	// 										},
	// 									},
	// 								},
	// 								AlternativeComments: comments("// Leading comment"),
	// 								Alternative: &ast.BlockStatement{
	// 									Meta: ast.New(T, 2),
	// 									Statements: []ast.Statement{
	// 										&ast.RestartStatement{
	// 											Meta: ast.New(T, 2),
	// 										},
	// 									},
	// 								},
	// 							},
	// 						},
	// 					},
	// 				},
	// 			},
	// 		}
	// 		vcl, err := New(lexer.NewFromString(input)).ParseVCL()
	// 		if err != nil {
	// 			t.Errorf("%+v", err)
	// 		}
	// 		assert(t, vcl, expect)
	// 	})
	//
	// 	t.Run("if else if else ", func(t *testing.T) {
	// 		input := `// Subroutine
	// sub vcl_recv {
	// 	// Leading comment
	// 	if (req.http.Host ~ "example.com") {
	// 		restart;
	// 	} else if (req.http.X-Forwarded-For ~ "192.168.0.1") {
	// 		restart;
	// 	} else {
	// 		restart;
	// 	}
	// }`
	// 		expect := &ast.VCL{
	// 			Statements: []ast.Statement{
	// 				&ast.SubroutineDeclaration{
	// 					Meta: ast.New(T, 0, comments("// Subroutine")),
	// 					Name: &ast.Ident{
	// 						Meta:  ast.New(T, 0),
	// 						Value: "vcl_recv",
	// 					},
	// 					Block: &ast.BlockStatement{
	// 						Meta: ast.New(T, 1),
	// 						Statements: []ast.Statement{
	// 							&ast.IfStatement{
	// 								Meta: ast.New(T, 1, comments("// Leading comment")),
	// 								Condition: &ast.InfixExpression{
	// 									Meta:     ast.New(T, 0),
	// 									Operator: "~",
	// 									Left: &ast.Ident{
	// 										Meta:  ast.New(T, 0),
	// 										Value: "req.http.Host",
	// 									},
	// 									Right: &ast.String{
	// 										Meta:  ast.New(T, 0),
	// 										Value: "example.com",
	// 									},
	// 								},
	// 								Consequence: &ast.BlockStatement{
	// 									Meta: ast.New(T, 2),
	// 									Statements: []ast.Statement{
	// 										&ast.RestartStatement{
	// 											Meta: ast.New(T, 2),
	// 										},
	// 									},
	// 								},
	// 								Another: []*ast.IfStatement{
	// 									{
	// 										Meta: ast.New(T, 1),
	// 										Condition: &ast.InfixExpression{
	// 											Meta:     ast.New(T, 0),
	// 											Operator: "~",
	// 											Left: &ast.Ident{
	// 												Meta:  ast.New(T, 0),
	// 												Value: "req.http.X-Forwarded-For",
	// 											},
	// 											Right: &ast.String{
	// 												Meta:  ast.New(T, 0),
	// 												Value: "192.168.0.1",
	// 											},
	// 										},
	// 										Consequence: &ast.BlockStatement{
	// 											Meta: ast.New(T, 2),
	// 											Statements: []ast.Statement{
	// 												&ast.RestartStatement{
	// 													Meta: ast.New(T, 2),
	// 												},
	// 											},
	// 										},
	// 									},
	// 								},
	// 								Alternative: &ast.BlockStatement{
	// 									Meta: ast.New(T, 2),
	// 									Statements: []ast.Statement{
	// 										&ast.RestartStatement{
	// 											Meta: ast.New(T, 2),
	// 										},
	// 									},
	// 								},
	// 							},
	// 						},
	// 					},
	// 				},
	// 			},
	// 		}
	// 		vcl, err := New(lexer.NewFromString(input)).ParseVCL()
	// 		if err != nil {
	// 			t.Errorf("%+v", err)
	// 		}
	// 		assert(t, vcl, expect)
	// 	})
	//
	// 	t.Run("if elseif else ", func(t *testing.T) {
	// 		input := `// Subroutine
	// sub vcl_recv {
	// 	// Leading comment
	// 	if (req.http.Host ~ "example.com") {
	// 		restart;
	// 	} elseif (req.http.X-Forwarded-For ~ "192.168.0.1") {
	// 		restart;
	// 	} else {
	// 		restart;
	// 	}
	// }`
	// 		expect := &ast.VCL{
	// 			Statements: []ast.Statement{
	// 				&ast.SubroutineDeclaration{
	// 					Meta: ast.New(T, 0, comments("// Subroutine")),
	// 					Name: &ast.Ident{
	// 						Meta:  ast.New(T, 0),
	// 						Value: "vcl_recv",
	// 					},
	// 					Block: &ast.BlockStatement{
	// 						Meta: ast.New(T, 1),
	// 						Statements: []ast.Statement{
	// 							&ast.IfStatement{
	// 								Meta: ast.New(T, 1, comments("// Leading comment")),
	// 								Condition: &ast.InfixExpression{
	// 									Meta:     ast.New(T, 0),
	// 									Operator: "~",
	// 									Left: &ast.Ident{
	// 										Meta:  ast.New(T, 0),
	// 										Value: "req.http.Host",
	// 									},
	// 									Right: &ast.String{
	// 										Meta:  ast.New(T, 0),
	// 										Value: "example.com",
	// 									},
	// 								},
	// 								Consequence: &ast.BlockStatement{
	// 									Meta: ast.New(T, 2),
	// 									Statements: []ast.Statement{
	// 										&ast.RestartStatement{
	// 											Meta: ast.New(T, 2),
	// 										},
	// 									},
	// 								},
	// 								Another: []*ast.IfStatement{
	// 									{
	// 										Meta: ast.New(T, 1),
	// 										Condition: &ast.InfixExpression{
	// 											Meta:     ast.New(T, 0),
	// 											Operator: "~",
	// 											Left: &ast.Ident{
	// 												Meta:  ast.New(T, 0),
	// 												Value: "req.http.X-Forwarded-For",
	// 											},
	// 											Right: &ast.String{
	// 												Meta:  ast.New(T, 0),
	// 												Value: "192.168.0.1",
	// 											},
	// 										},
	// 										Consequence: &ast.BlockStatement{
	// 											Meta: ast.New(T, 2),
	// 											Statements: []ast.Statement{
	// 												&ast.RestartStatement{
	// 													Meta: ast.New(T, 2),
	// 												},
	// 											},
	// 										},
	// 									},
	// 								},
	// 								Alternative: &ast.BlockStatement{
	// 									Meta: ast.New(T, 2),
	// 									Statements: []ast.Statement{
	// 										&ast.RestartStatement{
	// 											Meta: ast.New(T, 2),
	// 										},
	// 									},
	// 								},
	// 							},
	// 						},
	// 					},
	// 				},
	// 			},
	// 		}
	// 		vcl, err := New(lexer.NewFromString(input)).ParseVCL()
	// 		if err != nil {
	// 			t.Errorf("%+v", err)
	// 		}
	// 		assert(t, vcl, expect)
	// 	})
	//
	// 	t.Run("if elsif else ", func(t *testing.T) {
	// 		input := `// Subroutine
	// sub vcl_recv {
	// 	// Leading comment
	// 	if (req.http.Host ~ "example.com") {
	// 		restart;
	// 	} elsif (req.http.X-Forwarded-For ~ "192.168.0.1") {
	// 		restart;
	// 	} else {
	// 		restart;
	// 	}
	// }`
	// 		expect := &ast.VCL{
	// 			Statements: []ast.Statement{
	// 				&ast.SubroutineDeclaration{
	// 					Meta: ast.New(T, 0, comments("// Subroutine")),
	// 					Name: &ast.Ident{
	// 						Meta:  ast.New(T, 0),
	// 						Value: "vcl_recv",
	// 					},
	// 					Block: &ast.BlockStatement{
	// 						Meta: ast.New(T, 1),
	// 						Statements: []ast.Statement{
	// 							&ast.IfStatement{
	// 								Meta: ast.New(T, 1, comments("// Leading comment")),
	// 								Condition: &ast.InfixExpression{
	// 									Meta:     ast.New(T, 0),
	// 									Operator: "~",
	// 									Left: &ast.Ident{
	// 										Meta:  ast.New(T, 0),
	// 										Value: "req.http.Host",
	// 									},
	// 									Right: &ast.String{
	// 										Meta:  ast.New(T, 0),
	// 										Value: "example.com",
	// 									},
	// 								},
	// 								Consequence: &ast.BlockStatement{
	// 									Meta: ast.New(T, 2),
	// 									Statements: []ast.Statement{
	// 										&ast.RestartStatement{
	// 											Meta: ast.New(T, 2),
	// 										},
	// 									},
	// 								},
	// 								Another: []*ast.IfStatement{
	// 									{
	// 										Meta: ast.New(T, 1),
	// 										Condition: &ast.InfixExpression{
	// 											Meta:     ast.New(T, 0),
	// 											Operator: "~",
	// 											Left: &ast.Ident{
	// 												Meta:  ast.New(T, 0),
	// 												Value: "req.http.X-Forwarded-For",
	// 											},
	// 											Right: &ast.String{
	// 												Meta:  ast.New(T, 0),
	// 												Value: "192.168.0.1",
	// 											},
	// 										},
	// 										Consequence: &ast.BlockStatement{
	// 											Meta: ast.New(T, 2),
	// 											Statements: []ast.Statement{
	// 												&ast.RestartStatement{
	// 													Meta: ast.New(T, 2),
	// 												},
	// 											},
	// 										},
	// 									},
	// 								},
	// 								Alternative: &ast.BlockStatement{
	// 									Meta: ast.New(T, 2),
	// 									Statements: []ast.Statement{
	// 										&ast.RestartStatement{
	// 											Meta: ast.New(T, 2),
	// 										},
	// 									},
	// 								},
	// 							},
	// 						},
	// 					},
	// 				},
	// 			},
	// 		}
	// 		vcl, err := New(lexer.NewFromString(input)).ParseVCL()
	// 		if err != nil {
	// 			t.Errorf("%+v", err)
	// 		}
	// 		assert(t, vcl, expect)
	// 	})
}

//
// func TestParseUnsetStatement(t *testing.T) {
// 	input := `// Subroutine
// sub vcl_recv {
// 	// Leading comment
// 	unset req.http.Host; // Trailing comment
// }`
// 	expect := &ast.VCL{
// 		Statements: []ast.Statement{
// 			&ast.SubroutineDeclaration{
// 				Meta: ast.New(T, 0, comments("// Subroutine")),
// 				Name: &ast.Ident{
// 					Meta:  ast.New(T, 0),
// 					Value: "vcl_recv",
// 				},
// 				Block: &ast.BlockStatement{
// 					Meta: ast.New(T, 1),
// 					Statements: []ast.Statement{
// 						&ast.UnsetStatement{
// 							Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
// 							Ident: &ast.Ident{
// 								Meta:  ast.New(T, 0),
// 								Value: "req.http.Host",
// 							},
// 						},
// 					},
// 				},
// 			},
// 		},
// 	}
// 	vcl, err := New(lexer.NewFromString(input)).ParseVCL()
// 	if err != nil {
// 		t.Errorf("%+v", err)
// 	}
// 	assert(t, vcl, expect)
// }
//
// func TestParseAddStatement(t *testing.T) {
// 	t.Run("simple assign", func(t *testing.T) {
// 		input := `// Subroutine
// sub vcl_recv {
// 	// Leading comment
// 	add req.http.Cookie:session = "example.com"; // Trailing comment
// }`
// 		expect := &ast.VCL{
// 			Statements: []ast.Statement{
// 				&ast.SubroutineDeclaration{
// 					Meta: ast.New(T, 0, comments("// Subroutine")),
// 					Name: &ast.Ident{
// 						Meta:  ast.New(T, 0),
// 						Value: "vcl_recv",
// 					},
// 					Block: &ast.BlockStatement{
// 						Meta: ast.New(T, 1),
// 						Statements: []ast.Statement{
// 							&ast.AddStatement{
// 								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
// 								Ident: &ast.Ident{
// 									Meta:  ast.New(T, 0),
// 									Value: "req.http.Cookie:session",
// 								},
// 								Operator: &ast.Operator{
// 									Operator: "=",
// 								},
// 								Value: &ast.String{
// 									Meta:  ast.New(T, 0),
// 									Value: "example.com",
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 		}
// 		vcl, err := New(lexer.NewFromString(input)).ParseVCL()
// 		if err != nil {
// 			t.Errorf("%+v", err)
// 		}
// 		assert(t, vcl, expect)
// 	})
//
// 	t.Run("with string concatenation", func(t *testing.T) {
// 		input := `// Subroutine
// sub vcl_recv {
// 	// Leading comment
// 	add req.http.Host = "example" req.http.User-Agent "com"; // Trailing comment
// }`
// 		expect := &ast.VCL{
// 			Statements: []ast.Statement{
// 				&ast.SubroutineDeclaration{
// 					Meta: ast.New(T, 0, comments("// Subroutine")),
// 					Name: &ast.Ident{
// 						Meta:  ast.New(T, 0),
// 						Value: "vcl_recv",
// 					},
// 					Block: &ast.BlockStatement{
// 						Meta: ast.New(T, 1),
// 						Statements: []ast.Statement{
// 							&ast.AddStatement{
// 								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
// 								Ident: &ast.Ident{
// 									Meta:  ast.New(T, 0),
// 									Value: "req.http.Host",
// 								},
// 								Operator: &ast.Operator{
// 									Operator: "=",
// 								},
// 								Value: &ast.InfixExpression{
// 									Meta:     ast.New(T, 0),
// 									Operator: "+",
// 									Left: &ast.InfixExpression{
// 										Meta:     ast.New(T, 0),
// 										Operator: "+",
// 										Left: &ast.String{
// 											Meta:  ast.New(T, 0),
// 											Value: "example",
// 										},
// 										Right: &ast.Ident{
// 											Meta:  ast.New(T, 0),
// 											Value: "req.http.User-Agent",
// 										},
// 									},
// 									Right: &ast.String{
// 										Meta:  ast.New(T, 0),
// 										Value: "com",
// 									},
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 		}
// 		vcl, err := New(lexer.NewFromString(input)).ParseVCL()
// 		if err != nil {
// 			t.Errorf("%+v", err)
// 		}
// 		assert(t, vcl, expect)
// 	})
// }
//
// func TestCallStatement(t *testing.T) {
// 	input := `// Subroutine
// sub vcl_recv {
// 	// Leading comment
// 	call feature_mod_recv; // Trailing comment
// }`
// 	expect := &ast.VCL{
// 		Statements: []ast.Statement{
// 			&ast.SubroutineDeclaration{
// 				Meta: ast.New(T, 0, comments("// Subroutine")),
// 				Name: &ast.Ident{
// 					Meta:  ast.New(T, 0),
// 					Value: "vcl_recv",
// 				},
// 				Block: &ast.BlockStatement{
// 					Meta: ast.New(T, 1),
// 					Statements: []ast.Statement{
// 						&ast.CallStatement{
// 							Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
// 							Subroutine: &ast.Ident{
// 								Meta:  ast.New(T, 0),
// 								Value: "feature_mod_recv",
// 							},
// 						},
// 					},
// 				},
// 			},
// 		},
// 	}
// 	vcl, err := New(lexer.NewFromString(input)).ParseVCL()
// 	if err != nil {
// 		t.Errorf("%+v", err)
// 	}
// 	assert(t, vcl, expect)
// }
//
// func TestDeclareStatement(t *testing.T) {
// 	input := `// Subroutine
// sub vcl_recv {
// 	// Leading comment
// 	declare local var.foo STRING; // Trailing comment
// }`
//
// 	expect := &ast.VCL{
// 		Statements: []ast.Statement{
// 			&ast.SubroutineDeclaration{
// 				Meta: ast.New(T, 0, comments("// Subroutine")),
// 				Name: &ast.Ident{
// 					Meta:  ast.New(T, 0),
// 					Value: "vcl_recv",
// 				},
// 				Block: &ast.BlockStatement{
// 					Meta: ast.New(T, 1),
// 					Statements: []ast.Statement{
// 						&ast.DeclareStatement{
// 							Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
// 							Name: &ast.Ident{
// 								Meta:  ast.New(T, 0),
// 								Value: "var.foo",
// 							},
// 							ValueType: &ast.Ident{
// 								Meta:  ast.New(T, 0),
// 								Value: "STRING",
// 							},
// 						},
// 					},
// 				},
// 			},
// 		},
// 	}
// 	vcl, err := New(lexer.NewFromString(input)).ParseVCL()
// 	if err != nil {
// 		t.Errorf("%+v", err)
// 	}
// 	assert(t, vcl, expect)
// }
//
// func TestErrorStatement(t *testing.T) {
// 	t.Run("without argument", func(t *testing.T) {
// 		input := `// Subroutine
// sub vcl_recv {
// 	// Leading comment
// 	error 750; // Trailing comment
// }`
// 		expect := &ast.VCL{
// 			Statements: []ast.Statement{
// 				&ast.SubroutineDeclaration{
// 					Meta: ast.New(T, 0, comments("// Subroutine")),
// 					Name: &ast.Ident{
// 						Meta:  ast.New(T, 0),
// 						Value: "vcl_recv",
// 					},
// 					Block: &ast.BlockStatement{
// 						Meta: ast.New(T, 1),
// 						Statements: []ast.Statement{
// 							&ast.ErrorStatement{
// 								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
// 								Code: &ast.Integer{
// 									Meta:  ast.New(T, 0),
// 									Value: 750,
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 		}
// 		vcl, err := New(lexer.NewFromString(input)).ParseVCL()
// 		if err != nil {
// 			t.Errorf("%+v", err)
// 		}
// 		assert(t, vcl, expect)
// 	})
//
// 	t.Run("with argument", func(t *testing.T) {
// 		input := `// Subroutine
// sub vcl_recv {
// 	// Leading comment
// 	error 750 "/foobar/" req.http.Foo; // Trailing comment
// }`
// 		expect := &ast.VCL{
// 			Statements: []ast.Statement{
// 				&ast.SubroutineDeclaration{
// 					Meta: ast.New(T, 0, comments("// Subroutine")),
// 					Name: &ast.Ident{
// 						Meta:  ast.New(T, 0),
// 						Value: "vcl_recv",
// 					},
// 					Block: &ast.BlockStatement{
// 						Meta: ast.New(T, 1),
// 						Statements: []ast.Statement{
// 							&ast.ErrorStatement{
// 								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
// 								Code: &ast.Integer{
// 									Meta:  ast.New(T, 0),
// 									Value: 750,
// 								},
// 								Argument: &ast.InfixExpression{
// 									Meta: ast.New(T, 0),
// 									Left: &ast.String{
// 										Meta:  ast.New(T, 0),
// 										Value: "/foobar/",
// 									},
// 									Operator: "+",
// 									Right: &ast.Ident{
// 										Meta:  ast.New(T, 0),
// 										Value: "req.http.Foo",
// 									},
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 		}
// 		vcl, err := New(lexer.NewFromString(input)).ParseVCL()
// 		if err != nil {
// 			t.Errorf("%+v", err)
// 		}
// 		assert(t, vcl, expect)
// 	})
//
// 	t.Run("with ident argument", func(t *testing.T) {
// 		input := `// Subroutine
// sub vcl_recv {
// 	// Leading comment
// 	error var.IntValue; // Trailing comment
// }`
// 		expect := &ast.VCL{
// 			Statements: []ast.Statement{
// 				&ast.SubroutineDeclaration{
// 					Meta: ast.New(T, 0, comments("// Subroutine")),
// 					Name: &ast.Ident{
// 						Meta:  ast.New(T, 0),
// 						Value: "vcl_recv",
// 					},
// 					Block: &ast.BlockStatement{
// 						Meta: ast.New(T, 1),
// 						Statements: []ast.Statement{
// 							&ast.ErrorStatement{
// 								Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
// 								Code: &ast.Ident{
// 									Meta:  ast.New(T, 0),
// 									Value: "var.IntValue",
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 		}
// 		vcl, err := New(lexer.NewFromString(input)).ParseVCL()
// 		if err != nil {
// 			t.Errorf("%+v", err)
// 		}
// 		assert(t, vcl, expect)
// 	})
// }
//
// func TestLogStatement(t *testing.T) {
// 	input := `// Subroutine
// sub vcl_recv {
// 	// Leading comment
// 	log {"syslog "}
// 		{" fastly-log :: "} {"	timestamp:"}
// 		req.http.Timestamp
// 	; // Trailing comment
// }`
// 	expect := &ast.VCL{
// 		Statements: []ast.Statement{
// 			&ast.SubroutineDeclaration{
// 				Meta: ast.New(T, 0, comments("// Subroutine")),
// 				Name: &ast.Ident{
// 					Meta:  ast.New(T, 0),
// 					Value: "vcl_recv",
// 				},
// 				Block: &ast.BlockStatement{
// 					Meta: ast.New(T, 1),
// 					Statements: []ast.Statement{
// 						&ast.LogStatement{
// 							Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
// 							Value: &ast.InfixExpression{
// 								Meta:     ast.New(T, 0),
// 								Operator: "+",
// 								Right: &ast.Ident{
// 									Meta:  ast.New(T, 0),
// 									Value: "req.http.Timestamp",
// 								},
// 								Left: &ast.InfixExpression{
// 									Meta:     ast.New(T, 0),
// 									Operator: "+",
// 									Right: &ast.String{
// 										Meta: ast.New(T, 0),
// 										Value: "	timestamp:",
// 									},
// 									Left: &ast.InfixExpression{
// 										Meta:     ast.New(T, 0),
// 										Operator: "+",
// 										Right: &ast.String{
// 											Meta:  ast.New(T, 0),
// 											Value: " fastly-log :: ",
// 										},
// 										Left: &ast.String{
// 											Meta:  ast.New(T, 0),
// 											Value: "syslog ",
// 										},
// 									},
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 		},
// 	}
// 	vcl, err := New(lexer.NewFromString(input)).ParseVCL()
// 	if err != nil {
// 		t.Errorf("%+v", err)
// 	}
// 	assert(t, vcl, expect)
// }
//
// func TestReturnStatement(t *testing.T) {
// 	input := `// Subroutine
// sub vcl_recv {
// 	// Leading comment
// 	return(deliver); // Trailing comment
// }`
// 	expect := &ast.VCL{
// 		Statements: []ast.Statement{
// 			&ast.SubroutineDeclaration{
// 				Meta: ast.New(T, 0, comments("// Subroutine")),
// 				Name: &ast.Ident{
// 					Meta:  ast.New(T, 0),
// 					Value: "vcl_recv",
// 				},
// 				Block: &ast.BlockStatement{
// 					Meta: ast.New(T, 1),
// 					Statements: []ast.Statement{
// 						&ast.ReturnStatement{
// 							Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
// 							Ident: &ast.Ident{
// 								Meta:  ast.New(T, 0),
// 								Value: "deliver",
// 							},
// 						},
// 					},
// 				},
// 			},
// 		},
// 	}
// 	vcl, err := New(lexer.NewFromString(input)).ParseVCL()
// 	if err != nil {
// 		t.Errorf("%+v", err)
// 	}
// 	assert(t, vcl, expect)
// }
//
// func TestSyntheticStatement(t *testing.T) {
// 	input := `// Subroutine
// sub vcl_recv {
// 	// Leading comment
// 	synthetic {"Access "}
// 		{"denied"}; // Trailing comment
// }`
// 	expect := &ast.VCL{
// 		Statements: []ast.Statement{
// 			&ast.SubroutineDeclaration{
// 				Meta: ast.New(T, 0, comments("// Subroutine")),
// 				Name: &ast.Ident{
// 					Meta:  ast.New(T, 0),
// 					Value: "vcl_recv",
// 				},
// 				Block: &ast.BlockStatement{
// 					Meta: ast.New(T, 1),
// 					Statements: []ast.Statement{
// 						&ast.SyntheticStatement{
// 							Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
// 							Value: &ast.InfixExpression{
// 								Meta: ast.New(T, 0),
// 								Left: &ast.String{
// 									Meta:  ast.New(T, 0),
// 									Value: "Access ",
// 								},
// 								Operator: "+",
// 								Right: &ast.String{
// 									Meta:  ast.New(T, 0),
// 									Value: "denied",
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 		},
// 	}
// 	vcl, err := New(lexer.NewFromString(input)).ParseVCL()
// 	if err != nil {
// 		t.Errorf("%+v", err)
// 	}
// 	assert(t, vcl, expect)
// }
//
// func TestSyntheticBase64Statement(t *testing.T) {
// 	input := `// Subroutine
// sub vcl_recv {
// 	// Leading comment
// 	synthetic.base64 {"Access "}
// 		{"denied"}; // Trailing comment
// }`
// 	expect := &ast.VCL{
// 		Statements: []ast.Statement{
// 			&ast.SubroutineDeclaration{
// 				Meta: ast.New(T, 0, comments("// Subroutine")),
// 				Name: &ast.Ident{
// 					Meta:  ast.New(T, 0),
// 					Value: "vcl_recv",
// 				},
// 				Block: &ast.BlockStatement{
// 					Meta: ast.New(T, 1),
// 					Statements: []ast.Statement{
// 						&ast.SyntheticBase64Statement{
// 							Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
// 							Value: &ast.InfixExpression{
// 								Meta: ast.New(T, 0),
// 								Left: &ast.String{
// 									Meta:  ast.New(T, 0),
// 									Value: "Access ",
// 								},
// 								Operator: "+",
// 								Right: &ast.String{
// 									Meta:  ast.New(T, 0),
// 									Value: "denied",
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 		},
// 	}
// 	vcl, err := New(lexer.NewFromString(input)).ParseVCL()
// 	if err != nil {
// 		t.Errorf("%+v", err)
// 	}
// 	assert(t, vcl, expect)
// }
//
// func TestIfExpression(t *testing.T) {
// 	input := `// Subroutine
// sub vcl_recv {
// 	// Leading comment
// 	set req.http.Foo = if (req.http.Host, "example.com", "foobar"); // Trailing comment
// }`
//
// 	expect := &ast.VCL{
// 		Statements: []ast.Statement{
// 			&ast.SubroutineDeclaration{
// 				Meta: ast.New(T, 0, comments("// Subroutine")),
// 				Name: &ast.Ident{
// 					Meta:  ast.New(T, 0),
// 					Value: "vcl_recv",
// 				},
// 				Block: &ast.BlockStatement{
// 					Meta: ast.New(T, 1),
// 					Statements: []ast.Statement{
// 						&ast.SetStatement{
// 							Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
// 							Ident: &ast.Ident{
// 								Meta:  ast.New(T, 0),
// 								Value: "req.http.Foo",
// 							},
// 							Operator: &ast.Operator{
// 								Operator: "=",
// 							},
// 							Value: &ast.IfExpression{
// 								Meta: ast.New(T, 0),
// 								Condition: &ast.Ident{
// 									Meta:  ast.New(T, 0),
// 									Value: "req.http.Host",
// 								},
// 								Consequence: &ast.String{
// 									Meta:  ast.New(T, 0),
// 									Value: "example.com",
// 								},
// 								Alternative: &ast.String{
// 									Meta:  ast.New(T, 0),
// 									Value: "foobar",
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 		},
// 	}
// 	vcl, err := New(lexer.NewFromString(input)).ParseVCL()
// 	if err != nil {
// 		t.Errorf("%+v", err)
// 	}
// 	assert(t, vcl, expect)
// }
//
// func TestInfixIfExpression(t *testing.T) {
// 	input := `// Subroutine
// sub vcl_recv {
// 	// Leading comment
// 	log {"foo bar"}
// 		if (req.http.Host, "example.com", "foobar")
// 		{"baz"}; // Trailing comment
// }`
//
// 	expect := &ast.VCL{
// 		Statements: []ast.Statement{
// 			&ast.SubroutineDeclaration{
// 				Meta: ast.New(T, 0, comments("// Subroutine")),
// 				Name: &ast.Ident{
// 					Meta:  ast.New(T, 0),
// 					Value: "vcl_recv",
// 				},
// 				Block: &ast.BlockStatement{
// 					Meta: ast.New(T, 1),
// 					Statements: []ast.Statement{
// 						&ast.LogStatement{
// 							Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
// 							Value: &ast.InfixExpression{
// 								Meta:     ast.New(T, 0),
// 								Operator: "+",
// 								Right: &ast.String{
// 									Meta:  ast.New(T, 0),
// 									Value: "baz",
// 								},
// 								Left: &ast.InfixExpression{
// 									Meta:     ast.New(T, 0),
// 									Operator: "+",
// 									Left: &ast.String{
// 										Meta:  ast.New(T, 0),
// 										Value: "foo bar",
// 									},
// 									Right: &ast.IfExpression{
// 										Meta: ast.New(T, 0),
// 										Condition: &ast.Ident{
// 											Meta:  ast.New(T, 0),
// 											Value: "req.http.Host",
// 										},
// 										Consequence: &ast.String{
// 											Meta:  ast.New(T, 0),
// 											Value: "example.com",
// 										},
// 										Alternative: &ast.String{
// 											Meta:  ast.New(T, 0),
// 											Value: "foobar",
// 										},
// 									},
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 		},
// 	}
// 	vcl, err := New(lexer.NewFromString(input)).ParseVCL()
// 	if err != nil {
// 		t.Errorf("%+v", err)
// 	}
// 	assert(t, vcl, expect)
// }
//
// func TestFunctionCallExpression(t *testing.T) {
// 	t.Run("no argument", func(t *testing.T) {
// 		input := `// Subroutine
// sub vcl_recv {
// 	set req.http.X-Trace-Id = uuid.version4();
// }`
// 		expect := &ast.VCL{
// 			Statements: []ast.Statement{
// 				&ast.SubroutineDeclaration{
// 					Meta: ast.New(T, 0, comments("// Subroutine")),
// 					Name: &ast.Ident{
// 						Meta:  ast.New(T, 0),
// 						Value: "vcl_recv",
// 					},
// 					Block: &ast.BlockStatement{
// 						Meta: ast.New(T, 1),
// 						Statements: []ast.Statement{
// 							&ast.SetStatement{
// 								Meta: ast.New(T, 1),
// 								Ident: &ast.Ident{
// 									Meta:  ast.New(T, 0),
// 									Value: "req.http.X-Trace-Id",
// 								},
// 								Operator: &ast.Operator{
// 									Operator: "=",
// 								},
// 								Value: &ast.FunctionCallExpression{
// 									Meta: ast.New(T, 0),
// 									Function: &ast.Ident{
// 										Meta:  ast.New(T, 0),
// 										Value: "uuid.version4",
// 									},
// 									Arguments: []ast.Expression{},
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 		}
// 		vcl, err := New(lexer.NewFromString(input)).ParseVCL()
// 		if err != nil {
// 			t.Errorf("%+v", err)
// 		}
// 		assert(t, vcl, expect)
// 	})
//
// 	t.Run("some arguments", func(t *testing.T) {
// 		input := `// Subroutine
// sub vcl_recv {
// 	set req.http.X-Trace-Id = regsub(req.http.Host, "example.com", "");
// }`
// 		expect := &ast.VCL{
// 			Statements: []ast.Statement{
// 				&ast.SubroutineDeclaration{
// 					Meta: ast.New(T, 0, comments("// Subroutine")),
// 					Name: &ast.Ident{
// 						Meta:  ast.New(T, 0),
// 						Value: "vcl_recv",
// 					},
// 					Block: &ast.BlockStatement{
// 						Meta: ast.New(T, 1),
// 						Statements: []ast.Statement{
// 							&ast.SetStatement{
// 								Meta: ast.New(T, 1),
// 								Ident: &ast.Ident{
// 									Meta:  ast.New(T, 0),
// 									Value: "req.http.X-Trace-Id",
// 								},
// 								Operator: &ast.Operator{
// 									Operator: "=",
// 								},
// 								Value: &ast.FunctionCallExpression{
// 									Meta: ast.New(T, 0),
// 									Function: &ast.Ident{
// 										Meta:  ast.New(T, 0),
// 										Value: "regsub",
// 									},
// 									Arguments: []ast.Expression{
// 										&ast.Ident{
// 											Meta:  ast.New(T, 0),
// 											Value: "req.http.Host",
// 										},
// 										&ast.String{
// 											Meta:  ast.New(T, 0),
// 											Value: "example.com",
// 										},
// 										&ast.String{
// 											Meta:  ast.New(T, 0),
// 											Value: "",
// 										},
// 									},
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 		}
// 		vcl, err := New(lexer.NewFromString(input)).ParseVCL()
// 		if err != nil {
// 			t.Errorf("%+v", err)
// 		}
// 		assert(t, vcl, expect)
// 	})
// }
//
// func TestParseStringConcatExpression(t *testing.T) {
// 	input := `// Subroutine
// sub vcl_recv {
// 	declare local var.S STRING;
// 	set var.S = "foo" "bar" + "baz";
// }`
// 	_, err := New(lexer.NewFromString(input)).ParseVCL()
// 	if err != nil {
// 		t.Error(err)
// 	}
// }
//
// func TestCommentInInfixExpression(t *testing.T) {
// 	input := `
// sub vcl_recv {
// 	if (
// 		req.http.Host &&
// 		# Some comment here inside infix expressions
// 		req.http.Foo == "bar"
// 	) {
// 		set req.http.Host = "bar";
// 	}
// }`
// 	_, err := New(lexer.NewFromString(input)).ParseVCL()
// 	if err != nil {
// 		t.Errorf("%+v", err)
// 	}
// }
//
// func TestSetStatementWithGroupedExpression(t *testing.T) {
// 	input := `
// sub vcl_recv {
// 	set var.Bool = (var.IsOk && var.IsNg);
// }`
// 	expect := &ast.VCL{
// 		Statements: []ast.Statement{
// 			&ast.SubroutineDeclaration{
// 				Meta: ast.New(T, 0),
// 				Name: &ast.Ident{
// 					Meta:  ast.New(T, 0),
// 					Value: "vcl_recv",
// 				},
// 				Block: &ast.BlockStatement{
// 					Meta: ast.New(T, 1),
// 					Statements: []ast.Statement{
// 						&ast.SetStatement{
// 							Meta: ast.New(T, 1),
// 							Ident: &ast.Ident{
// 								Meta:  ast.New(T, 0),
// 								Value: "var.Bool",
// 							},
// 							Operator: &ast.Operator{
// 								Operator: "=",
// 							},
// 							Value: &ast.GroupedExpression{
// 								Meta: ast.New(T, 0),
// 								Right: &ast.InfixExpression{
// 									Meta: ast.New(T, 0),
// 									Left: &ast.Ident{
// 										Meta:  ast.New(T, 0),
// 										Value: "var.IsOk",
// 									},
// 									Operator: "&&",
// 									Right: &ast.Ident{
// 										Meta:  ast.New(T, 0),
// 										Value: "var.IsNg",
// 									},
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 		},
// 	}
// 	vcl, err := New(lexer.NewFromString(input)).ParseVCL()
// 	if err != nil {
// 		t.Errorf("%+v", err)
// 	}
// 	assert(t, vcl, expect)
// }
