package ast

import (
	"testing"
)

func TestAclDeclaration(t *testing.T) {
	acl := &AclDeclaration{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
		Name: &Ident{
			Meta:  New(T, 0, comments("/* before_name */"), comments("/* after_name */")),
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
			{
				Meta: New(T, 1),
				Inverse: &Boolean{
					Meta:  New(T, 0),
					Value: true,
				},
				IP: &IP{
					Meta:  New(T, 0, comments("/* foo */")),
					Value: "192.168.0.3",
				},
				Mask: &Integer{
					Meta:  New(T, 0, comments(), comments("/* bar */")),
					Value: 32,
				},
			},
		},
	}

	expect := `// This is comment
acl /* before_name */ internal /* after_name */ {
  // This is comment
  # This is another comment
  !"192.168.0.1"/32; // This is comment
  // This is comment
  # This is another comment
  "192.168.0.2"; // This is comment
  !/* foo */ "192.168.0.3"/32 /* bar */;
} // This is comment
`

	assert(t, acl.String(), expect)
}
