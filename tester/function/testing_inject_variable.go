package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Testing_inject_variable_Name = "testing.inject_variable"

func Testing_inject_variable_Validate(args []value.Value) error {
	if len(args) != 2 {
		return errors.ArgumentNotEnough(Testing_inject_variable_Name, 2, args)
	}
	if args[0].Type() != value.StringType {
		return errors.TypeMismatch(Testing_inject_variable_Name, 1, value.StringType, args[0].Type())
	}
	return nil
}

func Testing_inject_variable(
	ctx *context.Context,
	args ...value.Value,
) (value.Value, error) {

	if err := Testing_inject_variable_Validate(args); err != nil {
		return nil, errors.NewTestingError("%s", err.Error())
	}

	name := value.Unwrap[*value.String](args[0])

	// Important: second argument will be provided as literal
	// but overrided value must not be literal in the interpreter process
	// so we turn off the literal flag to false.
	// Unfortunately value.Value interface does not have to change the literal flag
	// so need type assertion for primitive values - it's annoying but just special case.
	switch t := args[1].(type) {
	case *value.Acl:
		t.Literal = false
	case *value.Backend:
		t.Literal = false
	case *value.Boolean:
		t.Literal = false
	case *value.Float:
		t.Literal = false
	case *value.IP:
		t.Literal = false
	case *value.Ident:
		t.Literal = false
	case *value.Integer:
		t.Literal = false
	case *value.RTime:
		t.Literal = false
	case *value.String:
		t.Literal = false
		// Note: *value.Time value could not be specified as literal
	}
	ctx.OverrideVariables[name.Value] = args[1]

	// If overriding request protocol, also set req.is_ssl accordingly
	if name.Value == "req.protocol" {
		if s, ok := args[1].(*value.String); ok {
			ctx.OverrideVariables["req.is_ssl"] = &value.Boolean{Value: s.Value == "https"}
		}
	}
	return value.Null, nil
}
