package ast

import (
	"testing"
)

func TestBackendDeclaration(t *testing.T) {
	backend := &BackendDeclaration{
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
			Value: "example",
		},
		Properties: []*BackendProperty{
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
				Key: &Ident{
					Value: "host",
				},
				Value: &String{
					Value: "example.com",
				},
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
				Key: &Ident{
					Value: "probe",
				},
				Value: &BackendProbeObject{
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
					Values: []*BackendProperty{
						{
							Meta: &Meta{
								Nest: 2,
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
							Key: &Ident{
								Value: "request",
							},
							Value: &String{
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
