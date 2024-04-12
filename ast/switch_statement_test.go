package ast

import (
	"testing"
)

func TestSwitchStatement(t *testing.T) {
	switchs := &SwitchStatement{
		Meta: New(T, 0, WithComments(CommentsMap{
			PlaceLeading:  comments("// This is comment"),
			PlaceTrailing: comments("/* This is comment */"),
		})),
		Control: &Ident{
			Meta:  New(T, 0),
			Value: "req.http.host",
		},
		Cases: []*CaseStatement{
			{
				Meta: New(T, 0, WithComments(CommentsMap{
					PlaceLeading:  comments("// This is comment"),
					PlaceTrailing: comments("/* This is comment */"),
				})),
				Test: &InfixExpression{
					Left:     &Ident{Value: "req.http.Host"},
					Operator: "==",
					Right: &String{
						Meta:  New(T, 0),
						Value: "1",
					},
				},
				Statements: []Statement{
					&BreakStatement{
						Meta: New(T, 1, WithComments(CommentsMap{
							PlaceLeading:  comments("// This is comment"),
							PlaceTrailing: comments("/* This is comment */"),
						})),
					},
				},
			},
			{
				Test: &InfixExpression{
					Left:     &Ident{Value: "req.http.Host"},
					Operator: "==",
					Right: &String{
						Meta:  New(T, 0),
						Value: "2",
					},
				},
				Meta: New(T, 0, WithComments(CommentsMap{
					PlaceLeading:  comments("// This is comment"),
					PlaceTrailing: comments("/* This is comment */"),
				})),
				Statements: []Statement{
					&FallthroughStatement{
						Meta: New(T, 1, WithComments(CommentsMap{
							PlaceLeading:  comments("// This is comment"),
							PlaceTrailing: comments("/* This is comment */"),
						})),
					},
				},
			},
			{
				Test: &InfixExpression{
					Left:     &Ident{Value: "req.http.Host"},
					Operator: "~",
					Right: &String{
						Meta:  New(T, 0),
						Value: "[3-4]",
					},
				},
				Meta: New(T, 0, WithComments(CommentsMap{
					PlaceLeading:  comments("// This is comment"),
					PlaceTrailing: comments("/* This is comment */"),
				})),
				Statements: []Statement{
					&BreakStatement{
						Meta: New(T, 1, WithComments(CommentsMap{
							PlaceLeading:  comments("// This is comment"),
							PlaceTrailing: comments("/* This is comment */"),
						})),
					},
				},
			},
			{
				Test: &InfixExpression{
					Left:     &Ident{Value: "req.http.Host"},
					Operator: "==",
					Right: &String{
						Meta:  New(T, 0),
						Value: "5",
					},
				},
				Meta: New(T, 0, WithComments(CommentsMap{
					PlaceLeading:  comments("// This is comment"),
					PlaceTrailing: comments("/* This is comment */"),
				})),
				Statements: []Statement{
					&BreakStatement{
						Meta: New(T, 1, WithComments(CommentsMap{
							PlaceLeading:  comments("// This is comment"),
							PlaceTrailing: comments("/* This is comment */"),
						})),
					},
				},
			},
			{
				Meta: New(T, 0, WithComments(CommentsMap{
					PlaceLeading:  comments("// This is comment"),
					PlaceTrailing: comments("/* This is comment */"),
				})),
				Statements: []Statement{
					&BreakStatement{
						Meta: New(T, 1, WithComments(CommentsMap{
							PlaceLeading:  comments("// This is comment"),
							PlaceTrailing: comments("/* This is comment */"),
						})),
					},
				},
			},
		},
	}

	expect := `// This is comment
switch (req.http.host) {
// This is comment
case "1": /* This is comment */
  // This is comment
  break; /* This is comment */
// This is comment
case "2": /* This is comment */
  // This is comment
  fallthrough; /* This is comment */
// This is comment
case ~"[3-4]": /* This is comment */
  // This is comment
  break; /* This is comment */
// This is comment
case "5": /* This is comment */
  // This is comment
  break; /* This is comment */
// This is comment
default: /* This is comment */
  // This is comment
  break; /* This is comment */
} /* This is comment */
`

	if switchs.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, switchs.String())
	}
}
