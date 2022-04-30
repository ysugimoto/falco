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
	"192.168.0.5"; // Trailing comment
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
						Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
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
							Meta: ast.New(T, 2),
							Values: []*ast.BackendProperty{
								{
									Meta: ast.New(T, 2, comments("// Leading comment"), comments("// Trailing comment")),
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

func TestParseTable(t *testing.T) {
	t.Run("with comma strictly", func(t *testing.T) {
		input := `// Table definition
table tbl {
	"foo": "bar",
	// Leading comment
	"lorem": "ipsum", // Trailing comment
	// Leading comment
	"dolor": "sit", // Trailing comment
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
							Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
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
							Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
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
					Meta: ast.New(T, 0, comments("// Table definition"), comments(), comments("// Trailing comment")),
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
							Meta: ast.New(T, 1, comments("// Leading comment"), comments("// Trailing comment")),
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
							Meta: ast.New(T, 1, comments("// Leading comment")),
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
		input := `// Table definition
table tbl {
}`

		expect := &ast.VCL{
			Statements: []ast.Statement{
				&ast.TableDeclaration{
					Meta: ast.New(T, 0, comments("// Table definition")),
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
							Meta:  ast.New(T, 1),
							Value: "quorum",
						},
						Value: &ast.String{
							Meta:  ast.New(T, 1),
							Value: "20%",
						},
					},
					&ast.DirectorBackendObject{
						Meta: ast.New(T, 2, comments("// Leading comment"), comments("// Trailing comment")),
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

func TestParsePenaltybox(t *testing.T) {
	input := `// Penaltybox definition
	penaltybox ip_pbox {
} // Trailing comment`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.PenaltyboxDeclaration{
				Meta: ast.New(T, 0, comments("// Penaltybox definition")),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "ip_pbox",
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
	input := `// Ratecounter definition
	ratecounter ip_ratecounter {
} // Trailing comment`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.RatecounterDeclaration{
				Meta: ast.New(T, 0, comments("// Ratecounter definition")),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "ip_ratecounter",
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
