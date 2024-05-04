package ast

import (
	"testing"
)

func TestDirectorDeclaration(t *testing.T) {
	director := &DirectorDeclaration{
		Meta: New(T, 0, comments("// leading comment"), comments("// trailing comment"), comments("// infix comment")),
		Name: &Ident{
			Meta:  New(T, 0, comments("/* before_name */"), comments("/* after_name */")),
			Value: "example",
		},
		DirectorType: &Ident{
			Meta:  New(T, 0, comments(), comments("/* after_type */")),
			Value: "client",
		},
		Properties: []Expression{
			&DirectorProperty{
				Meta: New(T, 1, comments("// This is comment", "# This is another comment"), comments("// This is comment")),
				Key: &Ident{
					Meta:  New(T, 0, comments(), comments("/* after_name */")),
					Value: "quorum",
				},
				Value: &PostfixExpression{
					Meta: New(T, 0, comments(), comments("/* after_value */")),
					Left: &Integer{
						Meta:  New(T, 0, comments("/* before_value */")),
						Value: 20,
					},
					Operator: "%",
				},
			},
			&DirectorBackendObject{
				Meta: New(T, 1, comments("// This is comment", "# This is another comment"), comments("// This is comment"), comments("/* trail_brace */")),
				Values: []*DirectorProperty{
					{
						Meta: New(T, 1),
						Key: &Ident{
							Meta:  New(T, 0, comments("/* inside_brace */")),
							Value: "request",
						},
						Value: &String{
							Meta:  New(T, 0),
							Value: "GET / HTTP/1.1",
						},
					},
					{
						Meta: New(T, 1),
						Key: &Ident{
							Meta:  New(T, 0, comments("/* leading */"), comments("/* after_name */")),
							Value: "weight",
						},
						Value: &Integer{
							Meta:  New(T, 0, comments("/* before_value */"), comments("/* after_value */")),
							Value: 1,
						},
					},
				},
			},
		},
	}

	expect := `// leading comment
director /* before_name */ example /* after_name */ client /* after_type */ {
  // This is comment
  # This is another comment
  .quorum /* after_name */ = /* before_value */ 20% /* after_value */; // This is comment
  // This is comment
  # This is another comment
  { /* inside_brace */ .request = "GET / HTTP/1.1"; /* leading */ .weight /* after_name */ = /* before_value */ 1 /* after_value */; /* trail_brace */ } // This is comment
  // infix comment
} // trailing comment
`

	assert(t, director.String(), expect)
}
