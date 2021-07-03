package ast

import (
	"testing"
)

func TestTableDeclaration(t *testing.T) {
	table := &TableDeclaration{
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
		ValueType: &Ident{
			Value: "STRING",
		},
		Properties: []*TableProperty{
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
				Key: &String{
					Value: "foo",
				},
				Value: &String{
					Value: "bar",
				},
			},
		},
	}

	expect := `// This is comment
table example STRING {
  // This is comment
  # This is another comment
  "foo": "bar", // This is comment
} // This is comment
`

	if table.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, table.String())
	}
}
