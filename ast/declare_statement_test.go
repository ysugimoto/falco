package ast

import (
	"testing"
)

func TestDeclareStatement(t *testing.T) {
	declare := &DeclareStatement{
		Meta: New(T, 0, comments("// leading comment"), comments("// trailing comment"), comments("/* before_local */")),
		Name: &Ident{
			Meta:  New(T, 0, comments("/* before_name */"), comments("/* after_name */")),
			Value: "var.Foo",
		},
		ValueType: &Ident{
			Meta:  New(T, 0, comments(), comments("/* after_type */")),
			Value: "STRING",
		},
	}

	expect := `// leading comment
declare /* before_local */ local /* before_name */ var.Foo /* after_name */ STRING /* after_type */; // trailing comment
`

	assert(t, declare.String(), expect)
}
