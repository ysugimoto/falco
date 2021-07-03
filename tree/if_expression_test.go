package ast

import (
	"testing"
)

func TestIfExpression(t *testing.T) {
	ife := &IfExpression{
		Meta: &Meta{
			Leading: []*Comment{
				{
					Value: "/* This is comment */",
				},
			},
			Trailing: []*Comment{
				{
					Value: "/* This is comment */",
				},
			},
		},
		Condition: &Ident{
			Value: "req.http.Host",
		},
		Consequence: &String{
			Value: "/foo",
		},
		Alternative: &String{
			Value: "/bar",
		},
	}

	expect := `/* This is comment */ if(req.http.Host, "/foo", "/bar") /* This is comment */`

	if ife.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, ife.String())
	}
}
