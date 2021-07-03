package ast

import (
	"testing"
)

func TestSubroutineStatement(t *testing.T) {
	sub := &SubroutineDeclaration{
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
		Name: &Ident{
			Value: "vcl_recv",
		},
		Block: &BlockStatement{
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
sub vcl_recv {
  // This is comment
  esi; /* This is comment */
} /* This is comment */
`

	if sub.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, sub.String())
	}
}
