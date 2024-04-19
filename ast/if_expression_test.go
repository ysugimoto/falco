package ast

import (
	"testing"
)

func TestIfExpression(t *testing.T) {
	ife := &IfExpression{
		Meta: New(T, 0, comments("/* leading */"), comments("/* trailing */")),
		Condition: &Ident{
			Meta:  New(T, 0, comments("/* before_condition */"), comments("/* after_condition */")),
			Value: "req.http.Host",
		},
		Consequence: &String{
			Meta:  New(T, 0, comments("/* before_consequence */"), comments("/* after_consequence */")),
			Value: "/foo",
		},
		Alternative: &String{
			Meta:  New(T, 0, comments("/* before_alternative */"), comments("/* after_alternative */")),
			Value: "/bar",
		},
	}

	expect := `/* leading */ if(/* before_condition */ req.http.Host /* after_condition */, /* before_consequence */ "/foo" /* after_consequence */, /* before_alternative */ "/bar" /* after_alternative */) /* trailing */`
	assert(t, ife.String(), expect)
}
