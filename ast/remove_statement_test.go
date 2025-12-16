package ast

import (
	"testing"
)

func TestRemoveStatement(t *testing.T) {
	remove := &RemoveStatement{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
		Ident: &Ident{
			Meta:  New(T, 0, comments("/* before_name */"), comments("/* after_name */")),
			Value: "req.http.Foo",
		},
	}

	expect := `// This is comment
remove /* before_name */ req.http.Foo /* after_name */; // This is comment
`
	assert(t, remove.String(), expect)
}
