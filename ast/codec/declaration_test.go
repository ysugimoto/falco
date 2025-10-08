package codec

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

func assertStatement[T ast.Statement](t *testing.T, input string, expect T) {
	vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Errorf("Unexpected parser error: %s", err)
		return
	}

	stmt, ok := vcl.Statements[0].(T)
	if !ok {
		t.Errorf("Unexpected type conversion error: %s", err)
		return
	}

	bin, err := NewEncoder().Encode(stmt)
	if err != nil {
		t.Errorf("Unexpected encode error: %s", err)
		return
	}
	dec := NewDecoder(bytes.NewReader(bin))
	actual, err := dec.decode(dec.nextFrame())
	if err != nil {
		t.Errorf("Unexpected decoding error: %s", err)
		return
	}
	if diff := cmp.Diff(actual, expect); diff != "" {
		t.Errorf("Decode result mismatch, diff=%s", diff)
	}
}

func TestAclDeclaration(t *testing.T) {
	input := `
acl test_acl {
  "192.168.0.1";
  !"192.168.0.2";
  "192.168.0.3"/32;
  !"192.168.0.4"/32;
}
`

	assertStatement(t, input, &ast.AclDeclaration{
		Name: &ast.Ident{
			Value: "test_acl",
		},
		CIDRs: []*ast.AclCidr{
			{
				IP: &ast.IP{Value: "192.168.0.1"},
			},
			{
				Inverse: &ast.Boolean{Value: true},
				IP:      &ast.IP{Value: "192.168.0.2"},
			},
			{
				IP:   &ast.IP{Value: "192.168.0.3"},
				Mask: &ast.Integer{Value: 32},
			},
			{
				Inverse: &ast.Boolean{Value: true},
				IP:      &ast.IP{Value: "192.168.0.4"},
				Mask:    &ast.Integer{Value: 32},
			},
		},
	})
}

func TestBackendDeclaration(t *testing.T) {
	input := `
backend example_com {
  .port = "443";
  .host = "example.com";
  .first_byte_timeout = 20s;
  .max_connections = 500;
  .between_bytes_timeout = 20s;
  .share_key = "xei5lohleex3Joh5ie5uy7du";
  .ssl = true;
  .ssl_sni_hostname = "example.com";
  .ssl_cert_hostname = "example.com";
  .ssl_check_cert = always;
  .min_tls_version = "1.2";
  .max_tls_version = "1.2";
  .bypass_local_route_table = false;
  .probe = {
    .request = "GET / HTTP/1.1" "Host: example.com" "Connection: close";
    .dummy = true;
    .threshold = 1;
    .window = 2;
    .timeout = 5s;
    .initial = 1;
    .expected_response = 200;
    .interval = 10s;
  }
}
`

	assertStatement(t, input, &ast.BackendDeclaration{
		Name: &ast.Ident{
			Value: "example_com",
		},
		Properties: []*ast.BackendProperty{
			{Key: &ast.Ident{Value: "port"}, Value: &ast.String{Value: "443"}},
			{Key: &ast.Ident{Value: "host"}, Value: &ast.String{Value: "example.com"}},
			{Key: &ast.Ident{Value: "first_byte_timeout"}, Value: &ast.RTime{Value: "20s"}},
			{Key: &ast.Ident{Value: "max_connections"}, Value: &ast.Integer{Value: 500}},
			{Key: &ast.Ident{Value: "between_bytes_timeout"}, Value: &ast.RTime{Value: "20s"}},
			{Key: &ast.Ident{Value: "share_key"}, Value: &ast.String{Value: "xei5lohleex3Joh5ie5uy7du"}},
			{Key: &ast.Ident{Value: "ssl"}, Value: &ast.Boolean{Value: true}},
			{Key: &ast.Ident{Value: "ssl_sni_hostname"}, Value: &ast.String{Value: "example.com"}},
			{Key: &ast.Ident{Value: "ssl_cert_hostname"}, Value: &ast.String{Value: "example.com"}},
			{Key: &ast.Ident{Value: "ssl_check_cert"}, Value: &ast.Ident{Value: "always"}},
			{Key: &ast.Ident{Value: "min_tls_version"}, Value: &ast.String{Value: "1.2"}},
			{Key: &ast.Ident{Value: "max_tls_version"}, Value: &ast.String{Value: "1.2"}},
			{Key: &ast.Ident{Value: "bypass_local_route_table"}, Value: &ast.Boolean{Value: false}},
			{
				Key: &ast.Ident{Value: "probe"},
				Value: &ast.BackendProbeObject{
					Values: []*ast.BackendProperty{
						{
							Key: &ast.Ident{Value: "request"},
							Value: &ast.InfixExpression{
								Left: &ast.InfixExpression{
									Left:     &ast.String{Value: "GET / HTTP/1.1"},
									Operator: "+",
									Right:    &ast.String{Value: "Host: example.com"},
								},
								Operator: "+",
								Right:    &ast.String{Value: "Connection: close"},
							},
						},
						{Key: &ast.Ident{Value: "dummy"}, Value: &ast.Boolean{Value: true}},
						{Key: &ast.Ident{Value: "threshold"}, Value: &ast.Integer{Value: 1}},
						{Key: &ast.Ident{Value: "window"}, Value: &ast.Integer{Value: 2}},
						{Key: &ast.Ident{Value: "timeout"}, Value: &ast.RTime{Value: "5s"}},
						{Key: &ast.Ident{Value: "initial"}, Value: &ast.Integer{Value: 1}},
						{Key: &ast.Ident{Value: "expected_response"}, Value: &ast.Integer{Value: 200}},
						{Key: &ast.Ident{Value: "interval"}, Value: &ast.RTime{Value: "10s"}},
					},
				},
			},
		},
	})
}

func TestDirectorDeclaration(t *testing.T) {
	input := `
director example client {
  .quorum = 20%;
  { .backend = F_origin_0; .weight = 1; }
  { .backend = F_origin_1; .weight = 1; }
  { .backend = F_origin_2; .weight = 1; }
}
`
	assertStatement(t, input, &ast.DirectorDeclaration{
		Name:         &ast.Ident{Value: "example"},
		DirectorType: &ast.Ident{Value: "client"},
		Properties: []ast.Expression{
			&ast.DirectorProperty{
				Key: &ast.Ident{Value: "quorum"},
				Value: &ast.PostfixExpression{
					Left:     &ast.Integer{Value: 20},
					Operator: "%",
				},
			},
			&ast.DirectorBackendObject{
				Values: []*ast.DirectorProperty{
					{
						Key:   &ast.Ident{Value: "backend"},
						Value: &ast.Ident{Value: "F_origin_0"},
					},
					{
						Key:   &ast.Ident{Value: "weight"},
						Value: &ast.Integer{Value: 1},
					},
				},
			},
			&ast.DirectorBackendObject{
				Values: []*ast.DirectorProperty{
					{
						Key:   &ast.Ident{Value: "backend"},
						Value: &ast.Ident{Value: "F_origin_1"},
					},
					{
						Key:   &ast.Ident{Value: "weight"},
						Value: &ast.Integer{Value: 1},
					},
				},
			},
			&ast.DirectorBackendObject{
				Values: []*ast.DirectorProperty{
					{
						Key:   &ast.Ident{Value: "backend"},
						Value: &ast.Ident{Value: "F_origin_2"},
					},
					{
						Key:   &ast.Ident{Value: "weight"},
						Value: &ast.Integer{Value: 1},
					},
				},
			},
		},
	})
}

func TestPenaltyboxDeclaration(t *testing.T) {
	input := `
penaltybox example {
}`

	assertStatement(t, input, &ast.PenaltyboxDeclaration{
		Name:  &ast.Ident{Value: "example"},
		Block: &ast.BlockStatement{},
	})
}

func TestRatecounterDeclaration(t *testing.T) {
	input := `
ratecounter example {
}`

	assertStatement(t, input, &ast.RatecounterDeclaration{
		Name:  &ast.Ident{Value: "example"},
		Block: &ast.BlockStatement{},
	})
}

func TestSubroutineDeclaration(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect *ast.SubroutineDeclaration
	}{
		{
			name: "lifecycle subroutine",
			input: `
sub vcl_recv {
	set req.http.Foo = "bar";
	restart;
}`,
			expect: &ast.SubroutineDeclaration{
				Name: &ast.Ident{Value: "vcl_recv"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.SetStatement{
							Ident: &ast.Ident{Value: "req.http.Foo"},
							Operator: &ast.Operator{
								Operator: "=",
							},
							Value: &ast.String{Value: "bar"},
						},
						&ast.RestartStatement{},
					},
				},
			},
		},
		{
			name: "functional subroutine",
			input: `
sub functional INTEGER {
	return 1;
}`,
			expect: &ast.SubroutineDeclaration{
				Name:       &ast.Ident{Value: "functional"},
				ReturnType: &ast.Ident{Value: "INTEGER"},
				Block: &ast.BlockStatement{
					Statements: []ast.Statement{
						&ast.ReturnStatement{
							ReturnExpression: &ast.Integer{Value: 1},
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

func TestTableDeclaration(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect *ast.TableDeclaration
	}{
		{
			name: "basic type",
			input: `
table example STRING {
	"foo": "bar",
	"lorem": "ipsum",
}`,
			expect: &ast.TableDeclaration{
				Name:      &ast.Ident{Value: "example"},
				ValueType: &ast.Ident{Value: "STRING"},
				Properties: []*ast.TableProperty{
					{
						Key:   &ast.String{Value: "foo"},
						Value: &ast.String{Value: "bar"},
					},
					{
						Key:   &ast.String{Value: "lorem"},
						Value: &ast.String{Value: "ipsum"},
					},
				},
			},
		},
		{
			name: "omitted value type (edge dictionary)",
			input: `
table example {
	"foo": "bar",
	"lorem": "ipsum",
}`,
			expect: &ast.TableDeclaration{
				Name: &ast.Ident{Value: "example"},
				Properties: []*ast.TableProperty{
					{
						Key:   &ast.String{Value: "foo"},
						Value: &ast.String{Value: "bar"},
					},
					{
						Key:   &ast.String{Value: "lorem"},
						Value: &ast.String{Value: "ipsum"},
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
