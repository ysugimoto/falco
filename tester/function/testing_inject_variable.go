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
		return nil, errors.NewTestingError(err.Error())
	}

	name := value.Unwrap[*value.String](args[0])
	ctx.OverrideVariables[name.Value] = args[1]
	return value.Null, nil
}
