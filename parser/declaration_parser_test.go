package parser

import (
	"testing"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/token"
)

func TestParseACL(t *testing.T) {
	input := `
// Acl definition
acl internal {
	"192.168.0.1";
	"192.168.0.2"/32;
	!"192.168.0.3";
	!"192.168.0.4"/32;
	// Leading comment
	"192.168.0.5"; // CIDR Trailing comment
	// Infix comment
} // Trailing comment
`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.AclDeclaration{
				Meta: ast.New(T, 0, comments("// Acl definition"), comments("// Trailing comment"), comments("// Infix comment")),
				Name: &ast.Ident{
					Meta:  ast.New(token.Token{}, 0),
					Value: "internal",
				},
				CIDRs: []*ast.AclCidr{
					{
						Meta: ast.New(token.Token{}, 1),
						IP: &ast.IP{
							Meta:  ast.New(token.Token{}, 1),
							Value: "192.168.0.1",
						},
					},
					{
						Meta: ast.New(token.Token{}, 1),
						IP: &ast.IP{
							Meta:  ast.New(token.Token{}, 1),
							Value: "192.168.0.2",
						},
						Mask: &ast.Integer{
							Meta:  ast.New(token.Token{}, 1),
							Value: 32,
						},
					},
					{
						Meta: ast.New(token.Token{}, 1),
						Inverse: &ast.Boolean{
							Meta:  ast.New(token.Token{}, 1),
							Value: true,
						},
						IP: &ast.IP{
							Meta:  ast.New(token.Token{}, 1),
							Value: "192.168.0.3",
						},
					},
					{
						Meta: ast.New(token.Token{}, 1),
						Inverse: &ast.Boolean{
							Meta:  ast.New(token.Token{}, 1),
							Value: true,
						},
						IP: &ast.IP{
							Meta:  ast.New(token.Token{}, 1),
							Value: "192.168.0.4",
						},
						Mask: &ast.Integer{
							Meta:  ast.New(token.Token{}, 1),
							Value: 32,
						},
					},
					{
						Meta: ast.New(T, 1, comments("// Leading comment"), comments("// CIDR Trailing comment")),
						IP: &ast.IP{
							Meta:  ast.New(token.Token{}, 1),
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

func TestParseAclWithComplexComments(t *testing.T) {
	input := `
// a
acl /* b */ internal /* c */{
    // d
	!/* e */"192.168.0.1" /* f */; // g
	// h
	"192.168.0.1"/32 /* i */ ;
	// j
} // k
`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.AclDeclaration{
				Meta: ast.New(T, 0, comments("// a"), comments("// k"), comments("// j")),
				Name: &ast.Ident{
					Meta:  ast.New(token.Token{}, 0, comments("/* b */"), comments("/* c */")),
					Value: "internal",
				},
				CIDRs: []*ast.AclCidr{
					{
						Meta: ast.New(token.Token{}, 1, comments("// d"), comments("// g")),
						Inverse: &ast.Boolean{
							Meta:  ast.New(token.Token{}, 1),
							Value: true,
						},
						IP: &ast.IP{
							Meta:  ast.New(token.Token{}, 1, comments("/* e */"), comments("/* f */")),
							Value: "192.168.0.1",
						},
					},
					{
						Meta: ast.New(token.Token{}, 1, comments("// h")),
						IP: &ast.IP{
							Meta:  ast.New(token.Token{}, 1),
							Value: "192.168.0.1",
						},
						Mask: &ast.Integer{
							Meta:  ast.New(token.Token{}, 1, comments(), comments("/* i */")),
							Value: 32,
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

func TestParseBackend(t *testing.T) {
	input := `// Backend Leading comment
backend example {
	// Host Leading comment
	.host = "example.com"; // Host Trailing comment
	.probe = {
		// Request Leading comment
		.request = "GET / HTTP/1.1"; // Request Trailing comment
		// Probe Infix comment
	} // Probe Trailing comment
	// Backend Infix comment
} // Backend Trailing comment`

	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.BackendDeclaration{
				Meta: ast.New(T, 0, comments("// Backend Leading comment"), comments("// Backend Trailing comment"), comments("// Backend Infix comment")),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "example",
				},
				Properties: []*ast.BackendProperty{
					{
						Meta: ast.New(T, 1, comments("// Host Leading comment"), comments("// Host Trailing comment")),
						Key: &ast.Ident{
							Meta:  ast.New(T, 1),
							Value: "host",
						},
						Value: &ast.String{
							Meta:  ast.New(T, 1),
							Value: "example.com",
						},
					},
					{
						Meta: ast.New(T, 1),
						Key: &ast.Ident{
							Meta:  ast.New(T, 1),
							Value: "probe",
						},
						Value: &ast.BackendProbeObject{
							Meta: ast.New(T, 2, ast.Comments{}, comments("// Probe Trailing comment"), comments("// Probe Infix comment")),
							Values: []*ast.BackendProperty{
								{
									Meta: ast.New(T, 2, comments("// Request Leading comment"), comments("// Request Trailing comment")),
									Key: &ast.Ident{
										Meta:  ast.New(T, 2),
										Value: "request",
									},
									Value: &ast.String{
										Meta:  ast.New(T, 2),
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

func TestParseBackendWithComplexComments(t *testing.T) {
	input := `// a
backend /* b */ example /* c */ {
	// d
	.host /* e */ = /* f */ "example.com" /* g */; // h
	.probe /* i */ = /* j */ {
		// k
		.request /* l */ = /* m */ "GET / HTTP/1.1" /* n */; // o
		// p
	} // q
	// r
} // s`

	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.BackendDeclaration{
				Meta: ast.New(T, 0, comments("// a"), comments("// s"), comments("// r")),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0, comments("/* b */"), comments("/* c */")),
					Value: "example",
				},
				Properties: []*ast.BackendProperty{
					{
						Meta: ast.New(T, 1, comments("// d"), comments("// h")),
						Key: &ast.Ident{
							Meta:  ast.New(T, 1, comments(), comments("/* e */")),
							Value: "host",
						},
						Value: &ast.String{
							Meta:  ast.New(T, 1, comments("/* f */"), comments("/* g */")),
							Value: "example.com",
						},
					},
					{
						Meta: ast.New(T, 1),
						Key: &ast.Ident{
							Meta:  ast.New(T, 1, comments(), comments("/* i */")),
							Value: "probe",
						},
						Value: &ast.BackendProbeObject{
							Meta: ast.New(T, 2, comments("/* j */"), comments("// q"), comments("// p")),
							Values: []*ast.BackendProperty{
								{
									Meta: ast.New(T, 2, comments("// k"), comments("// o")),
									Key: &ast.Ident{
										Meta:  ast.New(T, 2, comments(), comments("/* l */")),
										Value: "request",
									},
									Value: &ast.String{
										Meta:  ast.New(T, 2, comments("/* m */"), comments("/* n */")),
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
	t.Run("with comma strictly", func(t *testing.T) {
		input := `// Table Leading comment
table tbl {
	"foo": "bar",
	// Prop Leading comment
	"lorem": "ipsum", // Prop Trailing comment
	// Prop2 Leading comment
	"dolor": "sit", // Prop2 Trailing comment
	// Table Infix comment
} // Table Trailing comment`

		expect := &ast.VCL{
			Statements: []ast.Statement{
				&ast.TableDeclaration{
					Meta: ast.New(T, 0, comments("// Table Leading comment"), comments("// Table Trailing comment"), comments("// Table Infix comment")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "tbl",
					},
					Properties: []*ast.TableProperty{
						{
							Meta: ast.New(T, 1),
							Key: &ast.String{
								Meta:  ast.New(T, 1),
								Value: "foo",
							},
							Value: &ast.String{
								Meta:  ast.New(T, 1),
								Value: "bar",
							},
							HasComma: true,
						},
						{
							Meta: ast.New(T, 1, comments("// Prop Leading comment"), comments("// Prop Trailing comment")),
							Key: &ast.String{
								Meta:  ast.New(T, 1),
								Value: "lorem",
							},
							Value: &ast.String{
								Meta:  ast.New(T, 1),
								Value: "ipsum",
							},
							HasComma: true,
						},
						{
							Meta: ast.New(T, 1, comments("// Prop2 Leading comment"), comments("// Prop2 Trailing comment")),
							Key: &ast.String{
								Meta:  ast.New(T, 1),
								Value: "dolor",
							},
							Value: &ast.String{
								Meta:  ast.New(T, 1),
								Value: "sit",
							},
							HasComma: true,
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

	t.Run("without comma", func(t *testing.T) {
		input := `// Table Leading comment
table tbl {
 	"foo": "bar",
 	// Prop Leading comment
 	"lorem": "ipsum", // Prop Trailing comment
 	// Prop2 Leading comment
 	"dolor": "sit" // Prop2 Trailing comment
	// Table Infix comment
} // Table Trailing comment`

		expect := &ast.VCL{
			Statements: []ast.Statement{
				&ast.TableDeclaration{
					Meta: ast.New(T, 0, comments("// Table Leading comment"), comments("// Table Trailing comment"), comments("// Table Infix comment")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "tbl",
					},
					Properties: []*ast.TableProperty{
						{
							Meta: ast.New(T, 1),
							Key: &ast.String{
								Meta:  ast.New(T, 1),
								Value: "foo",
							},
							Value: &ast.String{
								Meta:  ast.New(T, 1),
								Value: "bar",
							},
							HasComma: true,
						},
						{
							Meta: ast.New(T, 1, comments("// Prop Leading comment"), comments("// Prop Trailing comment")),
							Key: &ast.String{
								Meta:  ast.New(T, 1),
								Value: "lorem",
							},
							Value: &ast.String{
								Meta:  ast.New(T, 1),
								Value: "ipsum",
							},
							HasComma: true,
						},
						{
							Meta: ast.New(T, 1, comments("// Prop2 Leading comment"), comments("// Prop2 Trailing comment")),
							Key: &ast.String{
								Meta:  ast.New(T, 1),
								Value: "dolor",
							},
							Value: &ast.String{
								Meta:  ast.New(T, 1),
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
	})

	t.Run("empty table", func(t *testing.T) {
		input := `// Table Leading comment
table tbl {
	// Table Infix comment
} // Table Trailing comment`

		expect := &ast.VCL{
			Statements: []ast.Statement{
				&ast.TableDeclaration{
					Meta: ast.New(T, 0, comments("// Table Leading comment"), comments("// Table Trailing comment"), comments("// Table Infix comment")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0),
						Value: "tbl",
					},
					Properties: []*ast.TableProperty{},
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

func TestParseTableWithComplexComments(t *testing.T) {
	t.Run("with ValueType", func(t *testing.T) {
		input := `// a
table /* b */ tbl /* c */ STRING /* d */ {
	/* e */
 	"foo" /* f */ : /* g */ "bar" /* h */, /* i */
	// j
 	"lorem": "ipsum" /* k */
	// l
} // m`

		expect := &ast.VCL{
			Statements: []ast.Statement{
				&ast.TableDeclaration{
					Meta: ast.New(T, 0, comments("// a"), comments("// m"), comments("// l")),
					Name: &ast.Ident{
						Meta:  ast.New(T, 0, comments("/* b */"), comments("/* c */")),
						Value: "tbl",
					},
					ValueType: &ast.Ident{
						Meta:  ast.New(T, 0, comments(), comments("/* d */")),
						Value: "STRING",
					},
					Properties: []*ast.TableProperty{
						{
							Meta: ast.New(T, 1, comments("/* e */"), comments("/* i */")),
							Key: &ast.String{
								Meta:  ast.New(T, 1, comments(), comments("/* f */")),
								Value: "foo",
							},
							Value: &ast.String{
								Meta:  ast.New(T, 1, comments("/* g */"), comments("/* h */")),
								Value: "bar",
							},
							HasComma: true,
						},
						{
							Meta: ast.New(T, 1, comments("// j"), comments("/* k */")),
							Key: &ast.String{
								Meta:  ast.New(T, 1),
								Value: "lorem",
							},
							Value: &ast.String{
								Meta:  ast.New(T, 1),
								Value: "ipsum",
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

func TestParseDirector(t *testing.T) {
	input := `// Director Leading comment
director example client {
	// Quorum Leading comment
	.quorum = 20 /* Quorum Infix comment */ %; // Quorum Trailing comment
	// Backend Leading comment
	{ .backend = example; .weight = 1; } // Backend Trailing comment
	// Director Infix comment
} // Director Trailing comment`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.DirectorDeclaration{
				Meta: ast.New(T, 0, comments("// Director Leading comment"), comments("// Director Trailing comment"), comments("// Director Infix comment")),
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
						Meta: ast.New(T, 1, comments("// Quorum Leading comment"), comments("// Quorum Trailing comment")),
						Key: &ast.Ident{
							Meta:  ast.New(T, 1),
							Value: "quorum",
						},
						Value: &ast.PostfixExpression{
							Meta: ast.New(T, 1, comments("/* Quorum Infix comment */")),
							Left: &ast.Integer{
								Meta:  ast.New(T, 1),
								Value: 20,
							},
							Operator: "%",
						},
					},
					&ast.DirectorBackendObject{
						Meta: ast.New(T, 2, comments("// Backend Leading comment"), comments("// Backend Trailing comment")),
						Values: []*ast.DirectorProperty{
							{
								Meta: ast.New(T, 2),
								Key: &ast.Ident{
									Meta:  ast.New(T, 2),
									Value: "backend",
								},
								Value: &ast.Ident{
									Meta:  ast.New(T, 2),
									Value: "example",
								},
							},
							{
								Meta: ast.New(T, 2),
								Key: &ast.Ident{
									Meta:  ast.New(T, 2),
									Value: "weight",
								},
								Value: &ast.Integer{
									Meta:  ast.New(T, 2),
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

func TestParseDirectorWithComplexComments(t *testing.T) {
	input := `// a
director /* b */ example/* c */client /* d */{
	// e
	.quorum /* f */ = /* g */20 /* h */ % /* i */; // j
	// k
	{/* l */ .backend /* m */ = /* n */ example /* o */; /* p */.weight /* q */= /* r */ 1 /* s */; /* t */ } // u
	// v
} // w`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.DirectorDeclaration{
				Meta: ast.New(T, 0, comments("// a"), comments("// w"), comments("// v")),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0, comments("/* b */"), comments("/* c */")),
					Value: "example",
				},
				DirectorType: &ast.Ident{
					Meta:  ast.New(T, 0, comments(), comments("/* d */")),
					Value: "client",
				},
				Properties: []ast.Expression{
					&ast.DirectorProperty{
						Meta: ast.New(T, 1, comments("// e"), comments("// j")),
						Key: &ast.Ident{
							Meta:  ast.New(T, 1, comments(), comments("/* f */")),
							Value: "quorum",
						},
						Value: &ast.PostfixExpression{
							Meta: ast.New(T, 1, comments("/* h */"), comments("/* i */")),
							Left: &ast.Integer{
								Meta:  ast.New(T, 1, comments("/* g */")),
								Value: 20,
							},
							Operator: "%",
						},
					},
					&ast.DirectorBackendObject{
						Meta: ast.New(T, 2, comments("// k"), comments("// u"), comments("/* t */")),
						Values: []*ast.DirectorProperty{
							{
								Meta: ast.New(T, 2, comments("/* l */")),
								Key: &ast.Ident{
									Meta:  ast.New(T, 2, comments(), comments("/* m */")),
									Value: "backend",
								},
								Value: &ast.Ident{
									Meta:  ast.New(T, 2, comments("/* n */"), comments("/* o */")),
									Value: "example",
								},
							},
							{
								Meta: ast.New(T, 2, comments("/* p */")),
								Key: &ast.Ident{
									Meta:  ast.New(T, 2, comments(), comments("/* q */")),
									Value: "weight",
								},
								Value: &ast.Integer{
									Meta:  ast.New(T, 2, comments("/* r */"), comments("/* s */")),
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

func TestParsePenaltybox(t *testing.T) {
	input := `// Penaltybox Leading comment
penaltybox ip_pbox {
  // Penaltybox Infix comment
} // Penaltybox Trailing comment`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.PenaltyboxDeclaration{
				Meta: ast.New(T, 0, comments("// Penaltybox Leading comment")),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "ip_pbox",
				},
				Block: &ast.BlockStatement{
					Meta:       ast.New(T, 1, ast.Comments{}, comments("// Penaltybox Trailing comment"), comments("// Penaltybox Infix comment")),
					Statements: []ast.Statement{},
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

func TestParseRatecounter(t *testing.T) {
	input := `// Ratecounter Leading comment
ratecounter ip_ratecounter {
	// Ratecounter Infix comment
} // Ratecounter Trailing comment`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.RatecounterDeclaration{
				Meta: ast.New(T, 0, comments("// Ratecounter Leading comment")),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "ip_ratecounter",
				},
				Block: &ast.BlockStatement{
					Meta:       ast.New(T, 1, ast.Comments{}, comments("// Ratecounter Trailing comment"), comments("// Ratecounter Infix comment")),
					Statements: []ast.Statement{},
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
