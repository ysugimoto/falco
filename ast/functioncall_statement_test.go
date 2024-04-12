package ast

import (
	"testing"
)

func TestFunctionCallStatement(t *testing.T) {
	fn := &FunctionCallStatement{
		Meta: New(T, 0, WithComments(CommentsMap{
			PlaceLeading:  comments("/* This is comment */"),
			PlaceTrailing: comments("/* This is comment */"),
		})),
		Function: &Ident{
			Meta:  New(T, 0),
			Value: "std.collect",
		},
		Arguments: []Expression{
			&String{
				Meta:  New(T, 0),
				Value: "req.http.Cookie",
			},
			&String{
				Meta:  New(T, 0),
				Value: ";",
			},
		},
	}

	expect := `/* This is comment */ std.collect("req.http.Cookie", ";") /* This is comment */`

	if fn.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, fn.String())
	}
}
