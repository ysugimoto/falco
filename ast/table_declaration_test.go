package ast

import (
	"testing"
)

func TestTableDeclaration(t *testing.T) {
	table := &TableDeclaration{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
		Name: &Ident{
			Meta:  New(T, 0),
			Value: "example",
		},
		ValueType: &Ident{
			Meta:  New(T, 0),
			Value: "STRING",
		},
		Properties: []*TableProperty{
			{
				Meta: New(T, 1, comments("// This is comment", "# This is another comment"), comments("// This is comment")),
				Key: &String{
					Meta:  New(T, 0),
					Value: "foo",
				},
				Value: &String{
					Meta:  New(T, 0),
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
