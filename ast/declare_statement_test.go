package ast

import (
	"testing"
)

func TestDeclareStatement(t *testing.T) {
	declare := &DeclareStatement{
		Meta: New(T, 0, comments("// leading comment"), comments("// trailing comment"), comments("/* before_local */")),
		Name: &Ident{
			Meta:  New(T, 0, comments("/* before_name */"), comments("/* after_name */")),
			Value: "var.Foo",
		},
		ValueType: &Ident{
			Meta:  New(T, 0, comments(), comments("/* after_type */")),
			Value: "STRING",
		},
	}

	expect := `// leading comment
declare /* before_local */ local /* before_name */ var.Foo /* after_name */ STRING /* after_type */; // trailing comment
`

	assert(t, declare.String(), expect)

	// Test with a string value
	declareWithStringValue := &DeclareStatement{
		Meta: New(T, 0),
		Name: &Ident{
			Meta:  New(T, 0),
			Value: "var.Foo",
		},
		ValueType: &Ident{
			Meta:  New(T, 0),
			Value: "STRING",
		},
		Value: &String{
			Meta:  New(T, 0),
			Value: "hello world",
		},
	}

	expectWithStringValue := `declare local var.Foo STRING = "hello world";
`

	assert(t, declareWithStringValue.String(), expectWithStringValue)

	// Test with a string value and comments
	declareWithStringValueAndComments := &DeclareStatement{
		Meta: New(T, 0, comments("// leading comment"), comments("// trailing comment"), comments("/* before_local */")),
		Name: &Ident{
			Meta:  New(T, 0, comments("/* before_name */"), comments("/* after_name */")),
			Value: "var.Foo",
		},
		ValueType: &Ident{
			Meta:  New(T, 0, comments(), comments("/* after_type */")),
			Value: "STRING",
		},
		Value: &String{
			Meta:  New(T, 0, comments(), comments("/* after_value */")),
			Value: "hello world",
		},
	}

	expectWithStringValueAndComments := `// leading comment
declare /* before_local */ local /* before_name */ var.Foo /* after_name */ STRING /* after_type */ = "hello world" /* after_value */; // trailing comment
`

	assert(t, declareWithStringValueAndComments.String(), expectWithStringValueAndComments)

	// Test with an integer value
	declareWithIntegerValue := &DeclareStatement{
		Meta: New(T, 0),
		Name: &Ident{
			Meta:  New(T, 0),
			Value: "var.answer",
		},
		ValueType: &Ident{
			Meta:  New(T, 0),
			Value: "INTEGER",
		},
		Value: &Integer{
			Meta:  New(T, 0),
			Value: 42,
		},
	}

	expectWithIntegerValue := `declare local var.answer INTEGER = 42;
`

	assert(t, declareWithIntegerValue.String(), expectWithIntegerValue)
}
