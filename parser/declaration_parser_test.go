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
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.ACL,
						Literal:  "acl",
						Line:     3,
						Position: 1,
					},
					Leading:            comments("// Acl definition"),
					Trailing:           comments("// Trailing comment"),
					Infix:              comments("// Infix comment"),
					Nest:               0,
					PreviousEmptyLines: 0,
					EndLine:            11,
					EndPosition:        1,
				},
				Name: &ast.Ident{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.IDENT,
							Literal:  "internal",
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
					Value: "internal",
				},
				CIDRs: []*ast.AclCidr{
					{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.STRING,
								Literal:  "192.168.0.1",
								Line:     4,
								Position: 2,
							},
							Leading:            comments(),
							Trailing:           comments(),
							Infix:              comments(),
							Nest:               1,
							PreviousEmptyLines: 0,
							EndLine:            4,
							EndPosition:        14,
						},
						IP: &ast.IP{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "192.168.0.1",
									Line:     4,
									Position: 2,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            4,
								EndPosition:        14,
							},
							Value: "192.168.0.1",
						},
					},
					{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.STRING,
								Literal:  "192.168.0.2",
								Line:     5,
								Position: 2,
							},
							Leading:            comments(),
							Trailing:           comments(),
							Infix:              comments(),
							Nest:               1,
							PreviousEmptyLines: 0,
							EndLine:            5,
							EndPosition:        17,
						},
						IP: &ast.IP{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "192.168.0.2",
									Line:     5,
									Position: 2,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            5,
								EndPosition:        14,
							},
							Value: "192.168.0.2",
						},
						Mask: &ast.Integer{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.INT,
									Literal:  "32",
									Line:     5,
									Position: 16,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            5,
								EndPosition:        17,
							},
							Value: 32,
						},
					},
					{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.NOT,
								Literal:  "!",
								Line:     6,
								Position: 2,
							},
							Leading:            comments(),
							Trailing:           comments(),
							Infix:              comments(),
							Nest:               1,
							PreviousEmptyLines: 0,
							EndLine:            6,
							EndPosition:        15,
						},
						Inverse: &ast.Boolean{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.NOT,
									Literal:  "!",
									Line:     6,
									Position: 2,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            0,
								EndPosition:        0,
							},
							Value: true,
						},
						IP: &ast.IP{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "192.168.0.3",
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
							Value: "192.168.0.3",
						},
					},
					{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.NOT,
								Literal:  "!",
								Line:     7,
								Position: 2,
							},
							Leading:            comments(),
							Trailing:           comments(),
							Infix:              comments(),
							Nest:               1,
							PreviousEmptyLines: 0,
							EndLine:            7,
							EndPosition:        18,
						},
						Inverse: &ast.Boolean{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.NOT,
									Literal:  "!",
									Line:     7,
									Position: 2,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
							},
							Value: true,
						},
						IP: &ast.IP{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "192.168.0.4",
									Line:     7,
									Position: 3,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            7,
								EndPosition:        15,
							},
							Value: "192.168.0.4",
						},
						Mask: &ast.Integer{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.INT,
									Literal:  "32",
									Line:     7,
									Position: 17,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            7,
								EndPosition:        18,
							},
							Value: 32,
						},
					},
					{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.STRING,
								Literal:  "192.168.0.5",
								Line:     9,
								Position: 2,
							},
							Leading:            comments("// Leading comment"),
							Trailing:           comments("// CIDR Trailing comment"),
							Infix:              comments(),
							Nest:               1,
							PreviousEmptyLines: 0,
							EndLine:            9,
							EndPosition:        14,
						},
						IP: &ast.IP{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "192.168.0.5",
									Line:     9,
									Position: 2,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            9,
								EndPosition:        14,
							},
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
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.ACL,
						Literal:  "acl",
						Line:     3,
						Position: 1,
					},
					Leading:            comments("// a"),
					Trailing:           comments("// k"),
					Infix:              comments("// j"),
					Nest:               0,
					PreviousEmptyLines: 0,
					EndLine:            9,
					EndPosition:        1,
				},
				Name: &ast.Ident{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.IDENT,
							Literal:  "internal",
							Line:     3,
							Position: 13,
						},
						Leading:            comments("/* b */"),
						Trailing:           comments("/* c */"),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            3,
						EndPosition:        20,
					},
					Value: "internal",
				},
				CIDRs: []*ast.AclCidr{
					{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.NOT,
								Literal:  "!",
								Line:     5,
								Position: 2,
							},
							Leading:            comments("// d"),
							Trailing:           comments("// g"),
							Infix:              comments(),
							Nest:               1,
							PreviousEmptyLines: 0,
							EndLine:            5,
							EndPosition:        22,
						},
						Inverse: &ast.Boolean{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.NOT,
									Literal:  "!",
									Line:     5,
									Position: 2,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
							},
							Value: true,
						},
						IP: &ast.IP{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "192.168.0.1",
									Line:     5,
									Position: 10,
								},
								Leading:            comments("/* e */"),
								Trailing:           comments("/* f */"),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            5,
								EndPosition:        22,
							},
							Value: "192.168.0.1",
						},
					},
					{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.STRING,
								Literal:  "192.168.0.1",
								Line:     7,
								Position: 2,
							},
							Leading:            comments("// h"),
							Trailing:           comments(),
							Infix:              comments(),
							Nest:               1,
							PreviousEmptyLines: 0,
							EndLine:            7,
							EndPosition:        17,
						},
						IP: &ast.IP{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "192.168.0.1",
									Line:     7,
									Position: 2,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            7,
								EndPosition:        14,
							},
							Value: "192.168.0.1",
						},
						Mask: &ast.Integer{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.INT,
									Literal:  "32",
									Line:     7,
									Position: 16,
								},
								Leading:            comments(),
								Trailing:           comments("/* i */"),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            7,
								EndPosition:        17,
							},
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
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.BACKEND,
						Literal:  "backend",
						Line:     2,
						Position: 1,
					},
					Leading:            comments("// Backend Leading comment"),
					Trailing:           comments("// Backend Trailing comment"),
					Infix:              comments("// Backend Infix comment"),
					Nest:               0,
					PreviousEmptyLines: 0,
					EndLine:            11,
					EndPosition:        1,
				},
				Name: &ast.Ident{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.IDENT,
							Literal:  "example",
							Line:     2,
							Position: 9,
						},
						Leading:            comments(),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            2,
						EndPosition:        15,
					},
					Value: "example",
				},
				Properties: []*ast.BackendProperty{
					{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.DOT,
								Literal:  ".",
								Line:     4,
								Position: 2,
							},
							Leading:            comments("// Host Leading comment"),
							Trailing:           comments("// Host Trailing comment"),
							Infix:              comments(),
							Nest:               1,
							PreviousEmptyLines: 0,
							EndLine:            4,
							EndPosition:        22,
						},
						Key: &ast.Ident{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.IDENT,
									Literal:  "host",
									Line:     4,
									Position: 3,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            4,
								EndPosition:        6,
							},
							Value: "host",
						},
						Value: &ast.String{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "example.com",
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
							Value: "example.com",
						},
					},
					{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.DOT,
								Literal:  ".",
								Line:     5,
								Position: 2,
							},
							Leading:            comments(),
							Trailing:           comments(),
							Infix:              comments(),
							Nest:               1,
							PreviousEmptyLines: 0,
							EndLine:            9,
							EndPosition:        2,
						},
						Key: &ast.Ident{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.IDENT,
									Literal:  "probe",
									Line:     5,
									Position: 3,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            5,
								EndPosition:        7,
							},
							Value: "probe",
						},
						Value: &ast.BackendProbeObject{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.LEFT_BRACE,
									Literal:  "{",
									Line:     5,
									Position: 11,
								},
								Leading:            comments(),
								Trailing:           comments("// Probe Trailing comment"),
								Infix:              comments("// Probe Infix comment"),
								Nest:               2,
								PreviousEmptyLines: 0,
								EndLine:            9,
								EndPosition:        2,
							},
							Values: []*ast.BackendProperty{
								{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.DOT,
											Literal:  ".",
											Line:     7,
											Position: 3,
										},
										Leading:            comments("// Request Leading comment"),
										Trailing:           comments("// Request Trailing comment"),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            7,
										EndPosition:        29,
									},
									Key: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "request",
												Line:     7,
												Position: 4,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            7,
											EndPosition:        10,
										},
										Value: "request",
									},
									Value: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "GET / HTTP/1.1",
												Line:     7,
												Position: 14,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            7,
											EndPosition:        29,
										},
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
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.BACKEND,
						Literal:  "backend",
						Line:     2,
						Position: 1,
					},
					Leading:            comments("// a"),
					Trailing:           comments("// s"),
					Infix:              comments("// r"),
					Nest:               0,
					PreviousEmptyLines: 0,
					EndLine:            11,
					EndPosition:        1,
				},
				Name: &ast.Ident{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.IDENT,
							Literal:  "example",
							Line:     2,
							Position: 17,
						},
						Leading:            comments("/* b */"),
						Trailing:           comments("/* c */"),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            2,
						EndPosition:        23,
					},
					Value: "example",
				},
				Properties: []*ast.BackendProperty{
					{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.DOT,
								Literal:  ".",
								Line:     4,
								Position: 2,
							},
							Leading:            comments("// d"),
							Trailing:           comments("// h"),
							Infix:              comments(),
							Nest:               1,
							PreviousEmptyLines: 0,
							EndLine:            4,
							EndPosition:        38,
						},
						Key: &ast.Ident{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.IDENT,
									Literal:  "host",
									Line:     4,
									Position: 3,
								},
								Leading:            comments(),
								Trailing:           comments("/* e */"),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            4,
								EndPosition:        6,
							},
							Value: "host",
						},
						Value: &ast.String{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "example.com",
									Line:     4,
									Position: 26,
								},
								Leading:            comments("/* f */"),
								Trailing:           comments("/* g */"),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            4,
								EndPosition:        38,
							},
							Value: "example.com",
						},
					},
					{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.DOT,
								Literal:  ".",
								Line:     5,
								Position: 2,
							},
							Leading:            comments(),
							Trailing:           comments(),
							Infix:              comments(),
							Nest:               1,
							PreviousEmptyLines: 0,
							EndLine:            9,
							EndPosition:        2,
						},
						Key: &ast.Ident{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.IDENT,
									Literal:  "probe",
									Line:     5,
									Position: 3,
								},
								Leading:            comments(),
								Trailing:           comments("/* i */"),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            5,
								EndPosition:        7,
							},
							Value: "probe",
						},
						Value: &ast.BackendProbeObject{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.LEFT_BRACE,
									Literal:  "{",
									Line:     5,
									Position: 27,
								},
								Leading:            comments("/* j */"),
								Trailing:           comments("// q"),
								Infix:              comments("// p"),
								Nest:               2,
								PreviousEmptyLines: 0,
								EndLine:            9,
								EndPosition:        2,
							},
							Values: []*ast.BackendProperty{
								{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.DOT,
											Literal:  ".",
											Line:     7,
											Position: 3,
										},
										Leading:            comments("// k"),
										Trailing:           comments("// o"),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            7,
										EndPosition:        45,
									},
									Key: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "request",
												Line:     7,
												Position: 4,
											},
											Leading:            comments(),
											Trailing:           comments("/* l */"),
											Infix:              comments(),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            7,
											EndPosition:        10,
										},
										Value: "request",
									},
									Value: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "GET / HTTP/1.1",
												Line:     7,
												Position: 30,
											},
											Leading:            comments("/* m */"),
											Trailing:           comments("/* n */"),
											Infix:              comments(),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            7,
											EndPosition:        45,
										},
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
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.TABLE,
							Literal:  "table",
							Line:     2,
							Position: 1,
						},
						Leading:            comments("// Table Leading comment"),
						Trailing:           comments("// Table Trailing comment"),
						Infix:              comments("// Table Infix comment"),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            9,
						EndPosition:        1,
					},
					Name: &ast.Ident{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.IDENT,
								Literal:  "tbl",
								Line:     2,
								Position: 7,
							},
							Leading:            comments(),
							Trailing:           comments(),
							Infix:              comments(),
							Nest:               0,
							PreviousEmptyLines: 0,
							EndLine:            2,
							EndPosition:        9,
						},
						Value: "tbl",
					},
					Properties: []*ast.TableProperty{
						{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "foo",
									Line:     3,
									Position: 2,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            3,
								EndPosition:        13,
							},
							Key: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "foo",
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
								Value: "foo",
							},
							Value: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "bar",
										Line:     3,
										Position: 9,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            3,
									EndPosition:        13,
								},
								Value: "bar",
							},
							HasComma: true,
						},
						{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "lorem",
									Line:     5,
									Position: 2,
								},
								Leading:            comments("// Prop Leading comment"),
								Trailing:           comments("// Prop Trailing comment"),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            5,
								EndPosition:        17,
							},
							Key: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "lorem",
										Line:     5,
										Position: 2,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            5,
									EndPosition:        8,
								},
								Value: "lorem",
							},
							Value: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "ipsum",
										Line:     5,
										Position: 11,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            5,
									EndPosition:        17,
								},
								Value: "ipsum",
							},
							HasComma: true,
						},
						{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "dolor",
									Line:     7,
									Position: 2,
								},
								Leading:            comments("// Prop2 Leading comment"),
								Trailing:           comments("// Prop2 Trailing comment"),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            7,
								EndPosition:        15,
							},
							Key: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "dolor",
										Line:     7,
										Position: 2,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            7,
									EndPosition:        8,
								},
								Value: "dolor",
							},
							Value: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "sit",
										Line:     7,
										Position: 11,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            7,
									EndPosition:        15,
								},
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
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.TABLE,
							Literal:  "table",
							Line:     2,
							Position: 1,
						},
						Leading:            comments("// Table Leading comment"),
						Trailing:           comments("// Table Trailing comment"),
						Infix:              comments("// Table Infix comment"),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            9,
						EndPosition:        1,
					},
					Name: &ast.Ident{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.IDENT,
								Literal:  "tbl",
								Line:     2,
								Position: 7,
							},
							Leading:            comments(),
							Trailing:           comments(),
							Infix:              comments(),
							Nest:               0,
							PreviousEmptyLines: 0,
							EndLine:            2,
							EndPosition:        9,
						},
						Value: "tbl",
					},
					Properties: []*ast.TableProperty{
						{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "foo",
									Line:     3,
									Position: 2,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            3,
								EndPosition:        13,
							},
							Key: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "foo",
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
								Value: "foo",
							},
							Value: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "bar",
										Line:     3,
										Position: 9,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            3,
									EndPosition:        13,
								},
								Value: "bar",
							},
							HasComma: true,
						},
						{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "lorem",
									Line:     5,
									Position: 2,
								},
								Leading:            comments("// Prop Leading comment"),
								Trailing:           comments("// Prop Trailing comment"),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            5,
								EndPosition:        17,
							},
							Key: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "lorem",
										Line:     5,
										Position: 2,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            5,
									EndPosition:        8,
								},
								Value: "lorem",
							},
							Value: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "ipsum",
										Line:     5,
										Position: 11,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            5,
									EndPosition:        17,
								},
								Value: "ipsum",
							},
							HasComma: true,
						},
						{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "dolor",
									Line:     7,
									Position: 2,
								},
								Leading:            comments("// Prop2 Leading comment"),
								Trailing:           comments("// Prop2 Trailing comment"),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            7,
								EndPosition:        15,
							},
							Key: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "dolor",
										Line:     7,
										Position: 2,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            7,
									EndPosition:        8,
								},
								Value: "dolor",
							},
							Value: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "sit",
										Line:     7,
										Position: 11,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            7,
									EndPosition:        15,
								},
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
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.TABLE,
							Literal:  "table",
							Line:     2,
							Position: 1,
						},
						Leading:            comments("// Table Leading comment"),
						Trailing:           comments("// Table Trailing comment"),
						Infix:              comments("// Table Infix comment"),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            4,
						EndPosition:        1,
					},
					Name: &ast.Ident{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.IDENT,
								Literal:  "tbl",
								Line:     2,
								Position: 7,
							},
							Leading:            comments(),
							Trailing:           comments(),
							Infix:              comments(),
							Nest:               0,
							PreviousEmptyLines: 0,
							EndLine:            2,
							EndPosition:        9,
						},
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
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.TABLE,
							Literal:  "table",
							Line:     2,
							Position: 1,
						},
						Leading:            comments("// a"),
						Trailing:           comments("// m"),
						Infix:              comments("// l"),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            8,
						EndPosition:        1,
					},
					Name: &ast.Ident{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.IDENT,
								Literal:  "tbl",
								Line:     2,
								Position: 15,
							},
							Leading:            comments("/* b */"),
							Trailing:           comments("/* c */"),
							Infix:              comments(),
							Nest:               0,
							PreviousEmptyLines: 0,
							EndLine:            2,
							EndPosition:        17,
						},
						Value: "tbl",
					},
					ValueType: &ast.Ident{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.IDENT,
								Literal:  "STRING",
								Line:     2,
								Position: 27,
							},
							Leading:            comments(),
							Trailing:           comments("/* d */"),
							Infix:              comments(),
							Nest:               0,
							PreviousEmptyLines: 0,
							EndLine:            2,
							EndPosition:        32,
						},
						Value: "STRING",
					},
					Properties: []*ast.TableProperty{
						{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "foo",
									Line:     4,
									Position: 2,
								},
								Leading:            comments("/* e */"),
								Trailing:           comments("/* i */"),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            4,
								EndPosition:        30,
							},
							Key: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "foo",
										Line:     4,
										Position: 2,
									},
									Leading:            comments(),
									Trailing:           comments("/* f */"),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            4,
									EndPosition:        6,
								},
								Value: "foo",
							},
							Value: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "bar",
										Line:     4,
										Position: 26,
									},
									Leading:            comments("/* g */"),
									Trailing:           comments("/* h */"),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            4,
									EndPosition:        30,
								},
								Value: "bar",
							},
							HasComma: true,
						},
						{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.STRING,
									Literal:  "lorem",
									Line:     6,
									Position: 2,
								},
								Leading:            comments("// j"),
								Trailing:           comments("/* k */"),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            6,
								EndPosition:        17,
							},
							Key: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "lorem",
										Line:     6,
										Position: 2,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            6,
									EndPosition:        8,
								},
								Value: "lorem",
							},
							Value: &ast.String{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.STRING,
										Literal:  "ipsum",
										Line:     6,
										Position: 11,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            6,
									EndPosition:        17,
								},
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
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.DIRECTOR,
						Literal:  "director",
						Line:     2,
						Position: 1,
					},
					Leading:            comments("// Director Leading comment"),
					Trailing:           comments("// Director Trailing comment"),
					Infix:              comments("// Director Infix comment"),
					Nest:               0,
					PreviousEmptyLines: 0,
					EndLine:            8,
					EndPosition:        1,
				},
				Name: &ast.Ident{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.IDENT,
							Literal:  "example",
							Line:     2,
							Position: 10,
						},
						Leading:            comments(),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            2,
						EndPosition:        16,
					},
					Value: "example",
				},
				DirectorType: &ast.Ident{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.IDENT,
							Literal:  "client",
							Line:     2,
							Position: 18,
						},
						Leading:            comments(),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            2,
						EndPosition:        23,
					},
					Value: "client",
				},
				Properties: []ast.Expression{
					&ast.DirectorProperty{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.DOT,
								Literal:  ".",
								Line:     4,
								Position: 2,
							},
							Leading:            comments("// Quorum Leading comment"),
							Trailing:           comments("// Quorum Trailing comment"),
							Infix:              comments(),
							Nest:               1,
							PreviousEmptyLines: 0,
							EndLine:            4,
							EndPosition:        42,
						},
						Key: &ast.Ident{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.IDENT,
									Literal:  "quorum",
									Line:     4,
									Position: 3,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            4,
								EndPosition:        8,
							},
							Value: "quorum",
						},
						Value: &ast.PostfixExpression{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.PERCENT,
									Literal:  "%",
									Line:     4,
									Position: 12,
								},
								Leading:            comments("/* Quorum Infix comment */"),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            4,
								EndPosition:        42,
							},
							Left: &ast.Integer{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.INT,
										Literal:  "20",
										Line:     4,
										Position: 12,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            4,
									EndPosition:        13,
								},
								Value: 20,
							},
							Operator: "%",
						},
					},
					&ast.DirectorBackendObject{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.LEFT_BRACE,
								Literal:  "{",
								Line:     6,
								Position: 2,
							},
							Leading:            comments("// Backend Leading comment"),
							Trailing:           comments("// Backend Trailing comment"),
							Infix:              comments(),
							Nest:               2,
							PreviousEmptyLines: 0,
							EndLine:            6,
							EndPosition:        37,
						},
						Values: []*ast.DirectorProperty{
							{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.DOT,
										Literal:  ".",
										Line:     6,
										Position: 4,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               2,
									PreviousEmptyLines: 0,
									EndLine:            6,
									EndPosition:        21,
								},
								Key: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.BACKEND,
											Literal:  "backend",
											Line:     6,
											Position: 5,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            6,
										EndPosition:        11,
									},
									Value: "backend",
								},
								Value: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "example",
											Line:     6,
											Position: 15,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            6,
										EndPosition:        21,
									},
									Value: "example",
								},
							},
							{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.DOT,
										Literal:  ".",
										Line:     6,
										Position: 24,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               2,
									PreviousEmptyLines: 0,
									EndLine:            6,
									EndPosition:        34,
								},
								Key: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "weight",
											Line:     6,
											Position: 25,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            6,
										EndPosition:        30,
									},
									Value: "weight",
								},
								Value: &ast.Integer{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.INT,
											Literal:  "1",
											Line:     6,
											Position: 34,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            6,
										EndPosition:        34,
									},
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
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.DIRECTOR,
						Literal:  "director",
						Line:     2,
						Position: 1,
					},
					Leading:            comments("// a"),
					Trailing:           comments("// w"),
					Infix:              comments("// v"),
					Nest:               0,
					PreviousEmptyLines: 0,
					EndLine:            8,
					EndPosition:        1,
				},
				Name: &ast.Ident{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.IDENT,
							Literal:  "example",
							Line:     2,
							Position: 18,
						},
						Leading:            comments("/* b */"),
						Trailing:           comments("/* c */"),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            2,
						EndPosition:        24,
					},
					Value: "example",
				},
				DirectorType: &ast.Ident{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.IDENT,
							Literal:  "client",
							Line:     2,
							Position: 32,
						},
						Leading:            comments(),
						Trailing:           comments("/* d */"),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            2,
						EndPosition:        37,
					},
					Value: "client",
				},
				Properties: []ast.Expression{
					&ast.DirectorProperty{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.DOT,
								Literal:  ".",
								Line:     4,
								Position: 2,
							},
							Leading:            comments("// e"),
							Trailing:           comments("// j"),
							Infix:              comments(),
							Nest:               1,
							PreviousEmptyLines: 0,
							EndLine:            4,
							EndPosition:        38,
						},
						Key: &ast.Ident{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.IDENT,
									Literal:  "quorum",
									Line:     4,
									Position: 3,
								},
								Leading:            comments(),
								Trailing:           comments("/* f */"),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            4,
								EndPosition:        8,
							},
							Value: "quorum",
						},
						Value: &ast.PostfixExpression{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.PERCENT,
									Literal:  "%",
									Line:     4,
									Position: 27,
								},
								Leading:            comments("/* h */"),
								Trailing:           comments("/* i */"),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            4,
								EndPosition:        38,
							},
							Left: &ast.Integer{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.INT,
										Literal:  "20",
										Line:     4,
										Position: 27,
									},
									Leading:            comments("/* g */"),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               1,
									PreviousEmptyLines: 0,
									EndLine:            4,
									EndPosition:        28,
								},
								Value: 20,
							},
							Operator: "%",
						},
					},
					&ast.DirectorBackendObject{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.LEFT_BRACE,
								Literal:  "{",
								Line:     6,
								Position: 2,
							},
							Leading:            comments("// k"),
							Trailing:           comments("// u"),
							Infix:              comments("/* t */"),
							Nest:               2,
							PreviousEmptyLines: 0,
							EndLine:            6,
							EndPosition:        106,
						},
						Values: []*ast.DirectorProperty{
							{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.DOT,
										Literal:  ".",
										Line:     6,
										Position: 11,
									},
									Leading:            comments("/* l */"),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               2,
									PreviousEmptyLines: 0,
									EndLine:            6,
									EndPosition:        44,
								},
								Key: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.BACKEND,
											Literal:  "backend",
											Line:     6,
											Position: 12,
										},
										Leading:            comments(),
										Trailing:           comments("/* m */"),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            6,
										EndPosition:        18,
									},
									Value: "backend",
								},
								Value: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "example",
											Line:     6,
											Position: 38,
										},
										Leading:            comments("/* n */"),
										Trailing:           comments("/* o */"),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            6,
										EndPosition:        44,
									},
									Value: "example",
								},
							},
							{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.DOT,
										Literal:  ".",
										Line:     6,
										Position: 62,
									},
									Leading:            comments("/* p */"),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               2,
									PreviousEmptyLines: 0,
									EndLine:            6,
									EndPosition:        87,
								},
								Key: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "weight",
											Line:     6,
											Position: 63,
										},
										Leading:            comments(),
										Trailing:           comments("/* q */"),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            6,
										EndPosition:        68,
									},
									Value: "weight",
								},
								Value: &ast.Integer{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.INT,
											Literal:  "1",
											Line:     6,
											Position: 87,
										},
										Leading:            comments("/* r */"),
										Trailing:           comments("/* s */"),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            6,
										EndPosition:        87,
									},
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
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.PENALTYBOX,
						Literal:  "penaltybox",
						Line:     2,
						Position: 1,
					},
					Leading:            comments("// Penaltybox Leading comment"),
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
							Literal:  "ip_pbox",
							Line:     2,
							Position: 12,
						},
						Leading:            comments(),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            2,
						EndPosition:        18,
					},
					Value: "ip_pbox",
				},
				Block: &ast.BlockStatement{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.LEFT_BRACE,
							Literal:  "{",
							Line:     2,
							Position: 20,
						},
						Leading:            comments(),
						Trailing:           comments("// Penaltybox Trailing comment"),
						Infix:              comments("// Penaltybox Infix comment"),
						Nest:               1,
						PreviousEmptyLines: 0,
						EndLine:            4,
						EndPosition:        1,
					},
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
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.RATECOUNTER,
						Literal:  "ratecounter",
						Line:     2,
						Position: 1,
					},
					Leading:            comments("// Ratecounter Leading comment"),
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
							Literal:  "ip_ratecounter",
							Line:     2,
							Position: 13,
						},
						Leading:            comments(),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            2,
						EndPosition:        26,
					},
					Value: "ip_ratecounter",
				},
				Block: &ast.BlockStatement{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.LEFT_BRACE,
							Literal:  "{",
							Line:     2,
							Position: 28,
						},
						Leading:            comments(),
						Trailing:           comments("// Ratecounter Trailing comment"),
						Infix:              comments("// Ratecounter Infix comment"),
						Nest:               1,
						PreviousEmptyLines: 0,
						EndLine:            4,
						EndPosition:        1,
					},
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
