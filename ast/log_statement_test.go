package ast

import (
	"testing"
)

func TestLogStatement(t *testing.T) {
	log := &LogStatement{
		Meta: New(T, 0, WithComments(CommentsMap{
			PlaceLeading:  comments("// This is comment"),
			PlaceTrailing: comments("// This is comment"),
		})),
		Value: &String{
			Meta:  New(T, 0),
			Value: "foobar",
		},
	}

	expect := `// This is comment
log "foobar"; // This is comment
`

	if log.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, log.String())
	}
}
