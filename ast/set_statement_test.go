package ast

import (
	"testing"
)

func TestSetStatement(t *testing.T) {
	set := &SetStatement{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
		Ident: &Ident{
			Meta:  New(T, 0, comments("/* before_name */"), comments("/* after_name */")),
			Value: "req.http.Host",
		},
		Operator: &Operator{
			Operator: "=",
		},
		Value: &String{
			Meta:  New(T, 0, comments("/* before_value */"), comments("/* after_value */")),
			Value: "example.com",
		},
	}

	expect := `// This is comment
set /* before_name */ req.http.Host /* after_name */ = /* before_value */ "example.com" /* after_value */; // This is comment
`

	assert(t, set.String(), expect)
}
