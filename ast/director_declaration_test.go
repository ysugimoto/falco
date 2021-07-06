package ast

import (
	"testing"
)

func TestDirectorDeclaration(t *testing.T) {
	director := &DirectorDeclaration{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
		Name: &Ident{
			Meta:  New(T, 0),
			Value: "example",
		},
		DirectorType: &Ident{
			Meta:  New(T, 0),
			Value: "client",
		},
		Properties: []Expression{
			&DirectorProperty{
				Meta: New(T, 1, comments("// This is comment", "# This is another comment"), comments("// This is comment")),
				Key: &Ident{
					Meta:  New(T, 0),
					Value: "quorum",
				},
				Value: &String{
					Meta:  New(T, 0),
					Value: "20%",
				},
			},
			&DirectorBackendObject{
				Meta: New(T, 1, comments("// This is comment", "# This is another comment"), comments("// This is comment")),
				Values: []*DirectorProperty{
					{
						Meta: New(T, 1, comments("// This is comment", "# This is another comment"), comments("// This is comment")),
						Key: &Ident{
							Meta:  New(T, 0),
							Value: "request",
						},
						Value: &String{
							Meta:  New(T, 0),
							Value: "GET / HTTP/1.1",
						},
					},
					{
						Meta: New(T, 1, comments("// This is comment", "# This is another comment"), comments("// This is comment")),
						Key: &Ident{
							Meta:  New(T, 0),
							Value: "weight",
						},
						Value: &Integer{
							Meta:  New(T, 0),
							Value: 1,
						},
					},
				},
			},
		},
	}

	expect := `// This is comment
director example client {
  // This is comment
  # This is another comment
  .quorum = "20%"; // This is comment
  // This is comment
  # This is another comment
  { .request = "GET / HTTP/1.1"; .weight = 1; } // This is comment
} // This is comment
`

	if director.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, director.String())
	}
}
