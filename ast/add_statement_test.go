package ast

import (
	"testing"
)

func TestAddStatement(t *testing.T) {
	add := &AddStatement{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
		Ident: &Ident{
			Meta:  New(T, 0, comments("/* a */"), comments("/* b */")),
			Value: "req.http.Host",
		},
		Operator: &Operator{
			Operator: "=",
		},
		Value: &String{
			Meta:  New(T, 0, comments("/* c */"), comments("/* d */")),
			Value: "example.com",
		},
	}

	expect := `// This is comment
add /* a */ req.http.Host /* b */ = /* c */ "example.com" /* d */; // This is comment
`

	assert(t, add.String(), expect)
}
