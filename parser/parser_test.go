package parser

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/lexer"
)

func assert(t *testing.T, actual, expect interface{}) {

	if diff := cmp.Diff(expect, actual,
		cmpopts.IgnoreFields(ast.AclDeclaration{}, "Token", "Comments"),
		cmpopts.IgnoreFields(ast.AclCidr{}, "Token", "Comments"),
		cmpopts.IgnoreFields(ast.BackendDeclaration{}, "Token", "Comments"),
		cmpopts.IgnoreFields(ast.BackendProperty{}, "Token", "Comments"),
		cmpopts.IgnoreFields(ast.BackendProbeObject{}, "Token"),
		cmpopts.IgnoreFields(ast.ImportStatement{}, "Token", "Comments"),
		cmpopts.IgnoreFields(ast.IncludeStatement{}, "Token", "Comments"),
		cmpopts.IgnoreFields(ast.DirectorDeclaration{}, "Token", "Comments"),
		cmpopts.IgnoreFields(ast.DirectorProperty{}, "Token", "Comments"),
		cmpopts.IgnoreFields(ast.DirectorBackendObject{}, "Token", "Comments"),
		cmpopts.IgnoreFields(ast.TableDeclaration{}, "Token", "Comments"),
		cmpopts.IgnoreFields(ast.TableProperty{}, "Token", "Comments"),
		cmpopts.IgnoreFields(ast.SubroutineDeclaration{}, "Token", "Comments"),
		cmpopts.IgnoreFields(ast.DeclareStatement{}, "Token", "Comments", "NestLevel"),
		cmpopts.IgnoreFields(ast.BlockStatement{}, "Token", "Comments", "NestLevel"),
		cmpopts.IgnoreFields(ast.SetStatement{}, "Token", "Comments", "NestLevel"),
		cmpopts.IgnoreFields(ast.InfixExpression{}, "Token"),
		cmpopts.IgnoreFields(ast.PrefixExpression{}, "Token"),
		cmpopts.IgnoreFields(ast.GroupedExpression{}, "Token"),
		cmpopts.IgnoreFields(ast.Operator{}, "Token"),
		cmpopts.IgnoreFields(ast.IfStatement{}, "Token", "Comments", "NestLevel", "AlternativeComments"),
		cmpopts.IgnoreFields(ast.Ident{}, "Token"),
		cmpopts.IgnoreFields(ast.Boolean{}, "Token"),
		cmpopts.IgnoreFields(ast.Integer{}, "Token"),
		cmpopts.IgnoreFields(ast.IP{}, "Token"),
		cmpopts.IgnoreFields(ast.String{}, "Token"),
		cmpopts.IgnoreFields(ast.UnsetStatement{}, "Token", "Comments", "NestLevel"),
		cmpopts.IgnoreFields(ast.AddStatement{}, "Token", "Comments", "NestLevel"),
		cmpopts.IgnoreFields(ast.CallStatement{}, "Token", "Comments", "NestLevel"),
		cmpopts.IgnoreFields(ast.ErrorStatement{}, "Token", "Comments", "NestLevel"),
		cmpopts.IgnoreFields(ast.LogStatement{}, "Token", "Comments", "NestLevel"),
		cmpopts.IgnoreFields(ast.ReturnStatement{}, "Token", "Comments", "NestLevel"),
		cmpopts.IgnoreFields(ast.SyntheticStatement{}, "Token", "Comments", "NestLevel"),
		cmpopts.IgnoreFields(ast.SyntheticBase64Statement{}, "Token", "Comments", "NestLevel"),
		cmpopts.IgnoreFields(ast.IfExpression{}, "Token"),
		cmpopts.IgnoreFields(ast.FunctionCallExpression{}, "Token"),
		cmpopts.IgnoreFields(ast.RestartStatement{}, "Token", "Comments", "NestLevel"),
		cmpopts.IgnoreFields(ast.EsiStatement{}, "Token", "Comments", "NestLevel"),
		cmpopts.IgnoreFields(ast.CommentStatement{}, "Token", "NestLevel"),
	); diff != "" {
		t.Errorf("Assertion error: diff=%s", diff)
	}
}

func TestParseImport(t *testing.T) {
	input := `import boltsort;`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.ImportStatement{
				Value: &ast.Ident{
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
	input := `include "feature_mod";`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.IncludeStatement{
				Module: &ast.String{
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

func TestParseACL(t *testing.T) {
	input := `
acl internal {
	"192.168.0.1";
	"192.168.0.2"/32;
	!"192.168.0.3";
	!"192.168.0.4"/32;
}`
	expect := &ast.AclDeclaration{
		Name: &ast.Ident{
			Value: "internal",
		},
		CIDRs: []*ast.AclCidr{
			{
				IP: &ast.IP{
					Value: "192.168.0.1",
				},
			},
			{
				IP: &ast.IP{
					Value: "192.168.0.2",
				},
				Mask: &ast.Integer{
					Value: 32,
				},
			},
			{
				Inverse: &ast.Boolean{
					Value: true,
				},
				IP: &ast.IP{
					Value: "192.168.0.3",
				},
			},
			{
				Inverse: &ast.Boolean{
					Value: true,
				},
				IP: &ast.IP{
					Value: "192.168.0.4",
				},
				Mask: &ast.Integer{
					Value: 32,
				},
			},
		},
	}
	vcl, err := New(lexer.NewFromString(input)).parseAclDeclaration(nil)
	if err != nil {
		t.Errorf("%+v", err)
	}
	assert(t, vcl, expect)
}

func TestParseBackend(t *testing.T) {
	input := `
backend example {
	.host = "example.com";
	.probe = {
		.request = "GET / HTTP/1.1";
	}
}`
	expect := &ast.BackendDeclaration{
		Name: &ast.Ident{
			Value: "example",
		},
		Properties: []*ast.BackendProperty{
			{
				Key:   &ast.Ident{Value: "host"},
				Value: &ast.String{Value: "example.com"},
			},
			{
				Key: &ast.Ident{Value: "probe"},
				Value: &ast.BackendProbeObject{
					Values: []*ast.BackendProperty{
						{
							Key:   &ast.Ident{Value: "request"},
							Value: &ast.String{Value: "GET / HTTP/1.1"},
						},
					},
				},
			},
		},
	}
	vcl, err := New(lexer.NewFromString(input)).parseBackendDeclaration(nil)
	if err != nil {
		t.Errorf("%+v", err)
	}
	assert(t, vcl, expect)
}

func TestParseTable(t *testing.T) {
	input := `
table tbl {
	"foo": "bar",
}`

	expect := &ast.TableDeclaration{
		Name: &ast.Ident{
			Value: "tbl",
		},
		Properties: []*ast.TableProperty{
			{
				Key: &ast.String{
					Value: "foo",
				},
				Value: &ast.String{
					Value: "bar",
				},
			},
		},
	}
	vcl, err := New(lexer.NewFromString(input)).parseTableDeclaration(nil)
	if err != nil {
		t.Errorf("%+v", err)
	}
	assert(t, vcl, expect)
}

func TestParseDirector(t *testing.T) {
	input := `
director example_director client {
	.quorum = 20%;
	{ .backend = example; .weight = 1; }
}`
	expect := &ast.DirectorDeclaration{
		Name: &ast.Ident{
			Value: "example_director",
		},
		DirectorType: &ast.Ident{
			Value: "client",
		},
		Properties: []ast.Expression{
			&ast.DirectorProperty{
				Key:   &ast.Ident{Value: "quorum"},
				Value: &ast.String{Value: "20%"},
			},
			&ast.DirectorBackendObject{
				Values: []*ast.DirectorProperty{
					&ast.DirectorProperty{
						Key:   &ast.Ident{Value: "backend"},
						Value: &ast.Ident{Value: "example"},
					},
					&ast.DirectorProperty{
						Key:   &ast.Ident{Value: "weight"},
						Value: &ast.Integer{Value: 1},
					},
				},
			},
		},
	}
	vcl, err := New(lexer.NewFromString(input)).parseDirectorDeclaration(nil)
	if err != nil {
		t.Errorf("%+v\n", err)
	}
	assert(t, vcl, expect)
}

func TestParseSetStatement(t *testing.T) {
	t.Run("simple assign", func(t *testing.T) {
		input := `set req.http.Host = "example.com";`
		expect := &ast.SetStatement{
			Ident: &ast.Ident{
				Value: "req.http.Host",
			},
			Operator: &ast.Operator{
				Operator: "=",
			},
			Value: &ast.String{
				Value: "example.com",
			},
		}
		vcl, err := New(lexer.NewFromString(input)).parseSetStatement()
		if err != nil {
			t.Errorf("%+v", err)
		}
		assert(t, vcl, expect)
	})

	t.Run("with string concatenation", func(t *testing.T) {
		input := `set req.http.Host = "example" req.http.User-Agent "com";`
		expect := &ast.SetStatement{
			Ident: &ast.Ident{
				Value: "req.http.Host",
			},
			Operator: &ast.Operator{
				Operator: "=",
			},
			Value: &ast.InfixExpression{
				Operator: "+",
				Left: &ast.InfixExpression{
					Operator: "+",
					Left: &ast.String{
						Value: "example",
					},
					Right: &ast.Ident{
						Value: "req.http.User-Agent",
					},
				},
				Right: &ast.String{
					Value: "com",
				},
			},
		}
		vcl, err := New(lexer.NewFromString(input)).parseSetStatement()
		if err != nil {
			t.Errorf("%+v", err)
		}
		assert(t, vcl, expect)
	})
}

func TestParseIfStatement(t *testing.T) {
	t.Run("only if", func(t *testing.T) {
		input := `
if (req.http.Host ~ "example.com") {
	restart;
}`
		expect := &ast.IfStatement{
			Condition: &ast.InfixExpression{
				Operator: "~",
				Left: &ast.Ident{
					Value: "req.http.Host",
				},
				Right: &ast.String{
					Value: "example.com",
				},
			},
			Consequence: &ast.BlockStatement{
				Statements: []ast.Statement{
					&ast.RestartStatement{},
				},
			},
		}
		vcl, err := New(lexer.NewFromString(input)).parseIfStatement()
		if err != nil {
			t.Errorf("%+v", err)
		}
		assert(t, vcl, expect)
	})

	t.Run("logical and condtions", func(t *testing.T) {
		input := `
if (req.http.Host ~ "example.com" && req.http.Host == "foobar") {
	restart;
}`
		expect := &ast.IfStatement{
			Condition: &ast.InfixExpression{
				Operator: "&&",
				Left: &ast.InfixExpression{
					Operator: "~",
					Left: &ast.Ident{
						Value: "req.http.Host",
					},
					Right: &ast.String{
						Value: "example.com",
					},
				},
				Right: &ast.InfixExpression{
					Operator: "==",
					Left: &ast.Ident{
						Value: "req.http.Host",
					},
					Right: &ast.String{
						Value: "foobar",
					},
				},
			},
			Consequence: &ast.BlockStatement{
				Statements: []ast.Statement{
					&ast.RestartStatement{},
				},
			},
		}
		vcl, err := New(lexer.NewFromString(input)).parseIfStatement()
		if err != nil {
			t.Errorf("%+v", err)
		}
		assert(t, vcl, expect)
	})

	t.Run("logical or condtions", func(t *testing.T) {
		input := `
if (req.http.Host ~ "example.com" || req.http.Host == "foobar") {
	restart;
}`
		expect := &ast.IfStatement{
			Condition: &ast.InfixExpression{
				Operator: "||",
				Left: &ast.InfixExpression{
					Operator: "~",
					Left: &ast.Ident{
						Value: "req.http.Host",
					},
					Right: &ast.String{
						Value: "example.com",
					},
				},
				Right: &ast.InfixExpression{
					Operator: "==",
					Left: &ast.Ident{
						Value: "req.http.Host",
					},
					Right: &ast.String{
						Value: "foobar",
					},
				},
			},
			Consequence: &ast.BlockStatement{
				Statements: []ast.Statement{
					&ast.RestartStatement{},
				},
			},
		}
		vcl, err := New(lexer.NewFromString(input)).parseIfStatement()
		if err != nil {
			t.Errorf("%+v", err)
		}
		assert(t, vcl, expect)
	})

	t.Run("if else", func(t *testing.T) {
		input := `
if (req.http.Host ~ "example.com") {
	restart;
} else {
	restart;
}`
		expect := &ast.IfStatement{
			Condition: &ast.InfixExpression{
				Operator: "~",
				Left: &ast.Ident{
					Value: "req.http.Host",
				},
				Right: &ast.String{
					Value: "example.com",
				},
			},
			Consequence: &ast.BlockStatement{
				Statements: []ast.Statement{
					&ast.RestartStatement{},
				},
			},
			Alternative: &ast.BlockStatement{
				Statements: []ast.Statement{
					&ast.RestartStatement{},
				},
			},
		}
		vcl, err := New(lexer.NewFromString(input)).parseIfStatement()
		if err != nil {
			t.Errorf("%+v", err)
		}
		assert(t, vcl, expect)
	})

	t.Run("if else if else ", func(t *testing.T) {
		input := `
if (req.http.Host ~ "example.com") {
	restart;
} else if (req.http.X-Forwarded-For ~ "192.168.0.1") {
	restart;
} else {
	restart;
}`
		expect := &ast.IfStatement{
			Condition: &ast.InfixExpression{
				Operator: "~",
				Left: &ast.Ident{
					Value: "req.http.Host",
				},
				Right: &ast.String{
					Value: "example.com",
				},
			},
			Consequence: &ast.BlockStatement{
				Statements: []ast.Statement{
					&ast.RestartStatement{},
				},
			},
			Another: []*ast.IfStatement{
				{
					Condition: &ast.InfixExpression{
						Operator: "~",
						Left: &ast.Ident{
							Value: "req.http.X-Forwarded-For",
						},
						Right: &ast.String{
							Value: "192.168.0.1",
						},
					},
					Consequence: &ast.BlockStatement{
						Statements: []ast.Statement{
							&ast.RestartStatement{},
						},
					},
				},
			},
			Alternative: &ast.BlockStatement{
				Statements: []ast.Statement{
					&ast.RestartStatement{},
				},
			},
		}
		vcl, err := New(lexer.NewFromString(input)).parseIfStatement()
		if err != nil {
			t.Errorf("%+v", err)
		}
		assert(t, vcl, expect)
	})

	t.Run("if elseif else ", func(t *testing.T) {
		input := `
if (req.http.Host ~ "example.com") {
	restart;
} elseif (req.http.X-Forwarded-For ~ "192.168.0.1") {
	restart;
} else {
	restart;
}`
		expect := &ast.IfStatement{
			Condition: &ast.InfixExpression{
				Operator: "~",
				Left: &ast.Ident{
					Value: "req.http.Host",
				},
				Right: &ast.String{
					Value: "example.com",
				},
			},
			Consequence: &ast.BlockStatement{
				Statements: []ast.Statement{
					&ast.RestartStatement{},
				},
			},
			Another: []*ast.IfStatement{
				{
					Condition: &ast.InfixExpression{
						Operator: "~",
						Left: &ast.Ident{
							Value: "req.http.X-Forwarded-For",
						},
						Right: &ast.String{
							Value: "192.168.0.1",
						},
					},
					Consequence: &ast.BlockStatement{
						Statements: []ast.Statement{
							&ast.RestartStatement{},
						},
					},
				},
			},
			Alternative: &ast.BlockStatement{
				Statements: []ast.Statement{
					&ast.RestartStatement{},
				},
			},
		}
		vcl, err := New(lexer.NewFromString(input)).parseIfStatement()
		if err != nil {
			t.Errorf("%+v", err)
		}
		assert(t, vcl, expect)
	})

	t.Run("if elsif else ", func(t *testing.T) {
		input := `
if (req.http.Host ~ "example.com") {
	restart;
} elsif (req.http.X-Forwarded-For ~ "192.168.0.1") {
	restart;
} else {
	restart;
}`
		expect := &ast.IfStatement{
			Condition: &ast.InfixExpression{
				Operator: "~",
				Left: &ast.Ident{
					Value: "req.http.Host",
				},
				Right: &ast.String{
					Value: "example.com",
				},
			},
			Consequence: &ast.BlockStatement{
				Statements: []ast.Statement{
					&ast.RestartStatement{},
				},
			},
			Another: []*ast.IfStatement{
				{
					Condition: &ast.InfixExpression{
						Operator: "~",
						Left: &ast.Ident{
							Value: "req.http.X-Forwarded-For",
						},
						Right: &ast.String{
							Value: "192.168.0.1",
						},
					},
					Consequence: &ast.BlockStatement{
						Statements: []ast.Statement{
							&ast.RestartStatement{},
						},
					},
				},
			},
			Alternative: &ast.BlockStatement{
				Statements: []ast.Statement{
					&ast.RestartStatement{},
				},
			},
		}
		vcl, err := New(lexer.NewFromString(input)).parseIfStatement()
		if err != nil {
			t.Errorf("%+v", err)
		}
		assert(t, vcl, expect)
	})
}

func TestParseUnsetStatement(t *testing.T) {
	input := `unset req.http.Host;`
	expect := &ast.UnsetStatement{
		Ident: &ast.Ident{
			Value: "req.http.Host",
		},
	}
	vcl, err := New(lexer.NewFromString(input)).parseUnsetStatement()
	if err != nil {
		t.Errorf("%+v", err)
	}
	assert(t, vcl, expect)
}

func TestParseAddStatement(t *testing.T) {
	t.Run("simple assign", func(t *testing.T) {
		input := `add req.http.Cookie:session = "example.com";`
		expect := &ast.AddStatement{
			Ident: &ast.Ident{
				Value: "req.http.Cookie:session",
			},
			Operator: &ast.Operator{
				Operator: "=",
			},
			Value: &ast.String{
				Value: "example.com",
			},
		}
		vcl, err := New(lexer.NewFromString(input)).parseAddStatement()
		if err != nil {
			t.Errorf("%+v", err)
		}
		assert(t, vcl, expect)
	})

	t.Run("with string concatenation", func(t *testing.T) {
		input := `add req.http.Host = "example" req.http.User-Agent "com";`
		expect := &ast.AddStatement{
			Ident: &ast.Ident{
				Value: "req.http.Host",
			},
			Operator: &ast.Operator{
				Operator: "=",
			},
			Value: &ast.InfixExpression{
				Operator: "+",
				Left: &ast.InfixExpression{
					Operator: "+",
					Left: &ast.String{
						Value: "example",
					},
					Right: &ast.Ident{
						Value: "req.http.User-Agent",
					},
				},
				Right: &ast.String{
					Value: "com",
				},
			},
		}
		vcl, err := New(lexer.NewFromString(input)).parseAddStatement()
		if err != nil {
			t.Errorf("%+v", err)
		}
		assert(t, vcl, expect)
	})
}

func TestCallStatement(t *testing.T) {
	input := `call feature_mod_recv;`
	expect := &ast.CallStatement{
		Subroutine: &ast.Ident{
			Value: "feature_mod_recv",
		},
	}
	vcl, err := New(lexer.NewFromString(input)).parseCallStatement()
	if err != nil {
		t.Errorf("%+v", err)
	}
	assert(t, vcl, expect)
}

func TestDeclareStatement(t *testing.T) {
	input := `declare local var.foo STRING;`
	expect := &ast.DeclareStatement{
		Name: &ast.Ident{
			Value: "var.foo",
		},
		ValueType: &ast.Ident{
			Value: "STRING",
		},
	}
	vcl, err := New(lexer.NewFromString(input)).parseDeclareStatement()
	if err != nil {
		t.Errorf("%+v", err)
	}
	assert(t, vcl, expect)
}

func TestErrorStatement(t *testing.T) {
	t.Run("without argument", func(t *testing.T) {
		input := `error 750;`
		expect := &ast.ErrorStatement{
			Code: &ast.Integer{
				Value: 750,
			},
		}
		vcl, err := New(lexer.NewFromString(input)).parseErrorStatement()
		if err != nil {
			t.Errorf("%+v", err)
		}
		assert(t, vcl, expect)
	})

	t.Run("with argument", func(t *testing.T) {
		input := `error 750 "/foobar";`
		expect := &ast.ErrorStatement{
			Code: &ast.Integer{
				Value: 750,
			},
			Argument: &ast.String{
				Value: "/foobar",
			},
		}
		vcl, err := New(lexer.NewFromString(input)).parseErrorStatement()
		if err != nil {
			t.Errorf("%+v", err)
		}
		assert(t, vcl, expect)
	})

	t.Run("with ident argument", func(t *testing.T) {
		input := `error var.IntValue;`
		expect := &ast.ErrorStatement{
			Code: &ast.Ident{
				Value: "var.IntValue",
			},
		}
		vcl, err := New(lexer.NewFromString(input)).parseErrorStatement()
		if err != nil {
			t.Errorf("%+v", err)
		}
		assert(t, vcl, expect)
	})
}

func TestLogStatement(t *testing.T) {
	input := `log {"syslog "} {" fastly-log :: "} {"	timestamp:"} req.http.Timestamp;`
	expect := &ast.LogStatement{
		Value: &ast.InfixExpression{
			Operator: "+",
			Right: &ast.Ident{
				Value: "req.http.Timestamp",
			},
			Left: &ast.InfixExpression{
				Operator: "+",
				Right: &ast.String{
					Value: "	timestamp:",
				},
				Left: &ast.InfixExpression{
					Operator: "+",
					Right: &ast.String{
						Value: " fastly-log :: ",
					},
					Left: &ast.String{
						Value: "syslog ",
					},
				},
			},
		},
	}
	vcl, err := New(lexer.NewFromString(input)).parseLogStatement()
	if err != nil {
		t.Errorf("%+v", err)
	}
	assert(t, vcl, expect)
}

func TestReturnStatement(t *testing.T) {
	input := `return(deliver);`
	expect := &ast.ReturnStatement{
		Ident: &ast.Ident{
			Value: "deliver",
		},
	}
	vcl, err := New(lexer.NewFromString(input)).parseReturnStatement()
	if err != nil {
		t.Errorf("%+v", err)
	}
	assert(t, vcl, expect)
}

func TestSyntheticStatement(t *testing.T) {
	input := `synthetic {"Access "} {"denined"};`
	expect := &ast.SyntheticStatement{
		Value: &ast.InfixExpression{
			Operator: "+",
			Right: &ast.String{
				Value: "denined",
			},
			Left: &ast.String{
				Value: "Access ",
			},
		},
	}
	vcl, err := New(lexer.NewFromString(input)).parseSyntheticStatement()
	if err != nil {
		t.Errorf("%+v", err)
	}
	assert(t, vcl, expect)
}

func TestSyntheticBase64Statement(t *testing.T) {
	input := `synthetic.base64 {"Access "} {"denined"};`
	expect := &ast.SyntheticBase64Statement{
		Value: &ast.InfixExpression{
			Operator: "+",
			Right: &ast.String{
				Value: "denined",
			},
			Left: &ast.String{
				Value: "Access ",
			},
		},
	}
	vcl, err := New(lexer.NewFromString(input)).parseSyntheticBase64Statement()
	if err != nil {
		t.Errorf("%+v", err)
	}
	assert(t, vcl, expect)
}

func TestIfExpression(t *testing.T) {
	input := `
if (req.http.Host, "example.com", "foobar");`

	expect := &ast.IfExpression{
		Condition: &ast.Ident{
			Value: "req.http.Host",
		},
		Consequence: &ast.String{
			Value: "example.com",
		},
		Alternative: &ast.String{
			Value: "foobar",
		},
	}
	vcl, err := New(lexer.NewFromString(input)).parseIfExpression()
	if err != nil {
		t.Errorf("%+v", err)
	}
	assert(t, vcl, expect)
}

func TestInfixIfExpression(t *testing.T) {
	input := `
log {"foo bar"} if (req.http.Host, "example.com", "foobar") {"baz"};`

	expect := &ast.LogStatement{
		Value: &ast.InfixExpression{
			Left: &ast.InfixExpression{
				Left: &ast.String{
					Value: "foo bar",
				},
				Operator: "+",
				Right: &ast.IfExpression{
					Condition: &ast.Ident{
						Value: "req.http.Host",
					},
					Consequence: &ast.String{
						Value: "example.com",
					},
					Alternative: &ast.String{
						Value: "foobar",
					},
				},
			},
			Operator: "+",
			Right: &ast.String{
				Value: "baz",
			},
		},
	}
	vcl, err := New(lexer.NewFromString(input)).parseLogStatement()
	if err != nil {
		t.Errorf("%+v", err)
	}
	assert(t, vcl, expect)
}

func TestFunctionCallExpression(t *testing.T) {
	t.Run("no argument", func(t *testing.T) {
		input := `uuid.version4();`
		expect := &ast.FunctionCallExpression{
			Function: &ast.Ident{
				Value: "uuid.version4",
			},
			Arguments: []ast.Expression{},
		}
		vcl, err := New(lexer.NewFromString(input)).parseExpression(LOWEST)
		if err != nil {
			t.Errorf("%+v", err)
		}
		assert(t, vcl, expect)
	})

	t.Run("some arguments", func(t *testing.T) {
		t.Skip()
		input := `regsub(req.http.Host, "foo", "bar");`
		expect := &ast.FunctionCallExpression{
			Function: &ast.Ident{
				Value: "regsub",
			},
			Arguments: []ast.Expression{
				&ast.Ident{
					Value: "req.http.Host",
				},
				&ast.String{
					Value: "foo",
				},
				&ast.String{
					Value: "bar",
				},
			},
		}
		vcl, err := New(lexer.NewFromString(input)).parseExpression(LOWEST)
		if err != nil {
			t.Errorf("%+v", err)
		}
		assert(t, vcl, expect)
	})
}

func TestAnnotationComment(t *testing.T) {
	input := `
// @recv
sub check_request {
}`

	expect := &ast.VCL{
		Statements: []ast.Statement{
			&ast.SubroutineDeclaration{
				Name: &ast.Ident{
					Value: "check_request",
				},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{},
				},
				Comments: ast.Comments{
					&ast.CommentStatement{
						Value: "// @recv",
					},
				},
			},
		},
	}

	vcl, err := New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Error(err)
	}
	assert(t, vcl, expect)

	sub := expect.Statements[0].(*ast.SubroutineDeclaration)
	annotations := sub.Comments.Annotations()

	if diff := cmp.Diff([]string{"recv"}, annotations); diff != "" {
		t.Errorf("annotations assertion error: diff=%s", diff)
	}

}

func TestParseStringConcatExpression(t *testing.T) {
	input := `
sub vcl_recv {
	declare local var.S STRING;
	set var.S = "foo" "bar" + "baz";
}`
	_, err := New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Error(err)
	}
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
	input := `set var.Bool = (var.IsOk && var.IsNg);`
	expect := &ast.SetStatement{
		Ident: &ast.Ident{
			Value: "var.Bool",
		},
		Operator: &ast.Operator{
			Operator: "=",
		},
		Value: &ast.GroupedExpression{
			Right: &ast.InfixExpression{
				Left: &ast.Ident{
					Value: "var.IsOk",
				},
				Operator: "&&",
				Right: &ast.Ident{
					Value: "var.IsNg",
				},
			},
		},
	}
	vcl, err := New(lexer.NewFromString(input)).parseSetStatement()
	if err != nil {
		t.Errorf("%+v", err)
	}
	assert(t, vcl, expect)
}
