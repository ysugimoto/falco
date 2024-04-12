package ast

import (
	"testing"
)

func TestRestartStatement(t *testing.T) {
	restart := &RestartStatement{
		Meta: New(T, 0, WithComments(CommentsMap{
			PlaceLeading:  comments("// This is comment"),
			PlaceTrailing: comments("// This is comment"),
		})),
	}

	expect := `// This is comment
restart; // This is comment
`

	if restart.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, restart.String())
	}
}
