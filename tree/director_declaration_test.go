package ast

import (
	"testing"
)

func TestDirectorDeclaration(t *testing.T) {
	director := &DirectorDeclaration{
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
		DirectorType: &Ident{
			Value: "client",
		},
		Properties: []Expression{
			&DirectorProperty{
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
					Value: "quorum",
				},
				Value: &String{
					Value: "20%",
				},
			},
			&DirectorBackendObject{
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
				Values: []*DirectorProperty{
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
							Value: "request",
						},
						Value: &String{
							Value: "GET / HTTP/1.1",
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
							Value: "weight",
						},
						Value: &Integer{
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
