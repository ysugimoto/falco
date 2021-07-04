package ast

import (
	"testing"
)

func TestIfExpression(t *testing.T) {
	ife := &IfExpression{
		Meta: New(T, 0, comments("/* This is comment */"), comments("/* This is comment */")),
		Condition: &Ident{
			Meta:  New(T, 0),
			Value: "req.http.Host",
		},
		Consequence: &String{
			Meta:  New(T, 0),
			Value: "/foo",
		},
		Alternative: &String{
			Meta:  New(T, 0),
			Value: "/bar",
		},
	}

	expect := `/* This is comment */ if(req.http.Host, "/foo", "/bar") /* This is comment */`

	if ife.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, ife.String())
	}
}
