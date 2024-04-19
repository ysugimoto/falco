package ast

import (
	"testing"
)

func TestGotoStatement(t *testing.T) {
	g := &GotoStatement{
		Meta: New(T, 0, comments("// leading comment"), comments("// trailing comment")),
		Destination: &Ident{
			Meta:  New(T, 0, comments("/* before_name */"), comments("/* after_name */")),
			Value: "update_and_set",
		},
	}

	expect := `// leading comment
goto /* before_name */ update_and_set /* after_name */; // trailing comment
`
	assert(t, g.String(), expect)
}
