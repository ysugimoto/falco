package ast

import (
	"testing"
)

func TestAclDeclaration(t *testing.T) {
	acl := &AclDeclaration{
		Meta: &Meta{
			Leading: []*Comment{
				{
					Value: "// This is comment",
				},
			},
			Trailing: []*Comment{
				{
					Value: "// This is comment",
				},
			},
		},
		Name: &Ident{
			Value: "internal",
		},
		CIDRs: []*AclCidr{
			{
				Meta: &Meta{
					Nest: 1,
					Leading: []*Comment{
						{
							Value: "// This is comment",
						},
						{
							Value: "# This is another comment",
						},
					},
					Trailing: []*Comment{
						{
							Value: "// This is comment",
						},
					},
				},
				Inverse: &Boolean{Value: true},
				IP:      &IP{Value: "192.168.0.1"},
				Mask:    &Integer{Value: 32},
			},
			{
				Meta: &Meta{
					Nest: 1,
					Leading: []*Comment{
						{
							Value: "// This is comment",
						},
						{
							Value: "# This is another comment",
						},
					},
					Trailing: []*Comment{
						{
							Value: "// This is comment",
						},
					},
				},
				Inverse: &Boolean{Value: false},
				IP:      &IP{Value: "192.168.0.2"},
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
