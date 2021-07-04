package ast

import (
	"testing"
)

func TestAclDeclaration(t *testing.T) {
	acl := &AclDeclaration{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
		Name: &Ident{
			Meta:  New(T, 0),
			Value: "internal",
		},
		CIDRs: []*AclCidr{
			{
				Meta: New(T, 1, comments("// This is comment", "# This is another comment"), comments("// This is comment")),
				Inverse: &Boolean{
					Meta:  New(T, 0),
					Value: true,
				},
				IP: &IP{
					Meta:  New(T, 0),
					Value: "192.168.0.1",
				},
				Mask: &Integer{
					Meta:  New(T, 0),
					Value: 32,
				},
			},
			{
				Meta: New(T, 1, comments("// This is comment", "# This is another comment"), comments("// This is comment")),
				Inverse: &Boolean{
					Meta:  New(T, 0),
					Value: false,
				},
				IP: &IP{
					Meta:  New(T, 0),
					Value: "192.168.0.2",
				},
			},
		},
	}

	expect := `// This is comment
acl internal {
  // This is comment
  # This is another comment
  !"192.168.0.1"/32; // This is comment
  // This is comment
  # This is another comment
  "192.168.0.2"; // This is comment
} // This is comment
`

	if acl.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, acl.String())
	}
}
