package codec

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

func assertCodec(t *testing.T, actual, expect ast.Statement) {
	c := New()
	bin := c.Encode(actual)
	dec, err := c.DecodeBytes(bin)
	if err != nil {
		t.Errorf("Unexpected decode error: %s", err)
		return
	}
	if diff := cmp.Diff(dec, expect); diff != "" {
		t.Errorf("Decoded mismatch, diff=%s", diff)
	}
}

func TestAclDeclarationCodec(t *testing.T) {
	input := `
acl test_acl {
	"192.168.0.1";
	!"10.0.0.1";
	"192.168.0.2"/32;
	!"192.168.0.3"/32;
}`
	vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Errorf("Unexpected parse error: %s", err)
		return
	}

	acl, ok := vcl.Statements[0].(*ast.AclDeclaration)
	if !ok {
		t.Errorf("Expects AclDeclaration, got %s", vcl.Statements[0].String())
		return
	}

	expect := &ast.AclDeclaration{
		Name: &ast.Ident{
			Value: "test_acl",
		},
		CIDRs: []*ast.AclCidr{
			{
				IP: &ast.IP{Value: "192.168.0.1"},
			},
			{
				Inverse: &ast.Boolean{Value: true},
				IP:      &ast.IP{Value: "192.168.0.1"},
			},
			{
				IP:   &ast.IP{Value: "192.168.0.1"},
				Mask: &ast.Integer{Value: 32},
			},
			{
				Inverse: &ast.Boolean{Value: true},
				IP:      &ast.IP{Value: "192.168.0.1"},
				Mask:    &ast.Integer{Value: 32},
			},
		},
	}

	assertCodec(t, acl, expect)
}
