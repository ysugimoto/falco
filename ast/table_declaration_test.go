package ast

import (
	"testing"
)

func TestTableDeclaration(t *testing.T) {
	table := &TableDeclaration{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
		Name: &Ident{
			Meta:  New(T, 0, comments("/* before_name */"), comments("/* after_name */")),
			Value: "example",
		},
		ValueType: &Ident{
			Meta:  New(T, 0, comments(), comments("/* after_type */")),
			Value: "STRING",
		},
		Properties: []*TableProperty{
			{
				Meta: New(T, 1, comments("// This is comment", "# This is another comment"), comments("// This is comment")),
				Key: &String{
					Meta:  New(T, 0, comments(), comments("/* after_key */")),
					Value: "foo",
				},
				Value: &String{
					Meta:  New(T, 0, comments("/* before_value */"), comments("/* after_value */")),
					Value: "bar",
				},
			},
		},
	}

	expect := `// This is comment
table /* before_name */ example /* after_name */ STRING /* after_type */ {
  // This is comment
  # This is another comment
  "foo" /* after_key */: /* before_value */ "bar" /* after_value */, // This is comment
} // This is comment
`

	assert(t, table.String(), expect)
}
