package ast

import (
	"testing"
)

func TestIfStatement(t *testing.T) {
	ifs := &IfStatement{
		Meta: &Meta{
			Leading: []*Comment{
				{
					Value: "// This is comment",
				},
			},
			Trailing: []*Comment{
				{
					Value: "/* This is comment */",
				},
			},
		},
		Condition: &Ident{
			Value: "req.http.Host",
		},
		Another: []*IfStatement{
			{
				Meta: &Meta{
					Leading: []*Comment{
						{
							Value: "// This is comment",
						},
					},
					Trailing: []*Comment{
						{
							Value: "/* This is comment */",
						},
					},
				},
				Condition: &Ident{
					Value: "req.http.Host",
				},
				Consequence: &BlockStatement{
					Meta: &Meta{
						Leading: []*Comment{
							{
								Value: "// This is comment",
							},
						},
						Trailing: []*Comment{
							{
								Value: "/* This is comment */",
							},
						},
					},
					Statements: []Statement{
						&EsiStatement{
							Meta: &Meta{
								Nest: 1,
								Leading: []*Comment{
									{
										Value: "// This is comment",
									},
								},
								Trailing: []*Comment{
									{
										Value: "/* This is comment */",
									},
								},
							},
						},
					},
				},
			},
		},
		Consequence: &BlockStatement{
			Meta: &Meta{
				Leading: []*Comment{
					{
						Value: "// This is comment",
					},
				},
				Trailing: []*Comment{
					{
						Value: "/* This is comment */",
					},
				},
			},
			Statements: []Statement{
				&EsiStatement{
					Meta: &Meta{
						Nest: 1,
						Leading: []*Comment{
							{
								Value: "// This is comment",
							},
						},
						Trailing: []*Comment{
							{
								Value: "/* This is comment */",
							},
						},
					},
				},
			},
		},
		AlternativeComments: Comments{
			{
				Value: "// This is comment",
			},
		},
		Alternative: &BlockStatement{
			Meta: &Meta{
				Leading: []*Comment{
					{
						Value: "// This is comment",
					},
				},
				Trailing: []*Comment{
					{
						Value: "/* This is comment */",
					},
				},
			},
			Statements: []Statement{
				&EsiStatement{
					Meta: &Meta{
						Nest: 1,
						Leading: []*Comment{
							{
								Value: "// This is comment",
							},
						},
						Trailing: []*Comment{
							{
								Value: "/* This is comment */",
							},
						},
					},
				},
			},
		},
	}

	expect := `// This is comment
if (req.http.Host) {
  // This is comment
  esi; /* This is comment */
}
// This is comment
else if (req.http.Host) {
  // This is comment
  esi; /* This is comment */
} /* This is comment */
// This is comment
else {
  // This is comment
  esi; /* This is comment */
} /* This is comment */
`

	if ifs.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, ifs.String())
	}
}
