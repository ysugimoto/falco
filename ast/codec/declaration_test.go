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

	bin := NewEncoder().Encode(stmt)
	actual, err := NewDecoder().Decode(bytes.NewReader(bin))
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
