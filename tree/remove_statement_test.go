package ast

import (
	"testing"
)

func TestRemoveStatement(t *testing.T) {
	remove := &RemoveStatement{
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
		Ident: &Ident{
			Value: "req.http.Foo",
		},
	}

	expect := `// This is comment
remove req.http.Foo; // This is comment
`

	if remove.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, remove.String())
	}
}
