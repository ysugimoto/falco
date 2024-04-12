package ast

import (
	"testing"
)

func TestBackendDeclaration(t *testing.T) {
	backend := &BackendDeclaration{
		Meta: New(T, 0, WithComments(CommentsMap{
			PlaceLeading:  comments("// This is comment"),
			PlaceTrailing: comments("// This is comment"),
		})),
		Name: &Ident{
			Meta:  New(T, 0),
			Value: "example",
		},
		Properties: []*BackendProperty{
			{
				Meta: New(T, 1, WithComments(CommentsMap{
					PlaceLeading:  comments("// This is comment", "# This is another comment"),
					PlaceTrailing: comments("// This is comment"),
				})),
				Key: &Ident{
					Meta:  New(T, 0),
					Value: "host",
				},
				Value: &String{
					Meta:  New(T, 0),
					Value: "example.com",
				},
			},
			{
				Meta: New(T, 1, WithComments(CommentsMap{
					PlaceLeading:  comments("// This is comment", "# This is another comment"),
					PlaceTrailing: comments("// This is comment"),
				})),
				Key: &Ident{
					Meta:  New(T, 0),
					Value: "probe",
				},
				Value: &BackendProbeObject{
					Meta: New(T, 1, WithComments(CommentsMap{
						PlaceLeading:  comments("// This is comment", "# This is another comment"),
						PlaceTrailing: comments("// This is comment"),
					})),
					Values: []*BackendProperty{
						{
							Meta: New(T, 2, WithComments(CommentsMap{
								PlaceLeading:  comments("// This is comment", "# This is another comment"),
								PlaceTrailing: comments("// This is comment"),
							})),
							Key: &Ident{
								Meta:  New(T, 0),
								Value: "request",
							},
							Value: &String{
								Meta:  New(T, 0),
								Value: "GET / HTTP/1.1",
							},
						},
					},
				},
			},
		},
	}

	expect := `// This is comment
backend example {
  // This is comment
  # This is another comment
  .host = "example.com"; // This is comment
  // This is comment
  # This is another comment
  .probe = {
    // This is comment
    # This is another comment
    .request = "GET / HTTP/1.1"; // This is comment
  } // This is comment
} // This is comment
`

	if backend.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, backend.String())
	}
}
