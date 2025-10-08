package ast

import (
	"testing"
)

func TestBackendDeclaration(t *testing.T) {
	backend := &BackendDeclaration{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
		Name: &Ident{
			Meta:  New(T, 0, comments("/* before_name */"), comments("/* after_name */")),
			Value: "example",
		},
		Properties: []*BackendProperty{
			{
				Meta: New(T, 1, comments("// This is comment", "# This is another comment"), comments("// This is comment")),
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
				Meta: New(T, 1),
				Key: &Ident{
					Meta:  New(T, 0, comments(), comments("/* after_name */")),
					Value: "port",
				},
				Value: &String{
					Meta:  New(T, 0, comments("/* before_value */"), comments("/* after_value */")),
					Value: "443",
				},
			},
			{
				Meta: New(T, 1, comments("// This is comment", "# This is another comment"), comments("// This is comment")),
				Key: &Ident{
					Meta:  New(T, 0),
					Value: "probe",
				},
				Value: &BackendProbeObject{
					Meta: New(T, 1, comments("// This is comment", "# This is another comment"), comments("// This is comment")),
					Values: []*BackendProperty{
						{
							Meta: New(T, 2, comments("// This is comment", "# This is another comment"), comments("// This is comment")),
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
backend /* before_name */ example /* after_name */ {
  // This is comment
  # This is another comment
  .host = "example.com"; // This is comment
  .port /* after_name */ = /* before_value */ "443" /* after_value */;
  // This is comment
  # This is another comment
  .probe = {
    // This is comment
    # This is another comment
    .request = "GET / HTTP/1.1"; // This is comment
  } // This is comment
} // This is comment
`

	assert(t, backend.String(), expect)
}
