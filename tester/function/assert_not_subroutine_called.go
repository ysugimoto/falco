package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_not_subroutine_called_Name = "assert.not_subroutine_called"

func Assert_not_subroutine_called_Validate(args []value.Value) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.ArgumentNotInRange(Assert_not_subroutine_called_Name, 1, 2, args)
	}

	if args[0].Type() != value.StringType {
		return errors.TypeMismatch(Assert_not_subroutine_called_Name, 1, value.StringType, args[0].Type())
	}
	return nil
}

func Assert_not_subroutine_called(ctx *context.Context, args ...value.Value) (value.Value, error) {
	if err := Assert_not_subroutine_called_Validate(args); err != nil {
		return nil, errors.NewTestingError("%s", err.Error())
	}

	name := value.Unwrap[*value.String](args[0]).Value

	// Check custom message
	var message string
	if len(args) == 2 { // (name, message)
		if args[1].Type() != value.StringType {
			return &value.Boolean{}, errors.NewTestingError(
				"%s: 2nd argument must be STRING, %s provided",
				Assert_not_subroutine_called_Name, args[1].Type(),
			)
		}
		message = value.Unwrap[*value.String](args[1]).Value
	}

	_, ok := ctx.SubroutineCalls[name]
	if ok {
		if message != "" {
			return &value.Boolean{}, errors.NewAssertionError(args[0], "%s", message)
		}
		return &value.Boolean{}, errors.NewAssertionError(args[0], "Subroutine %s is called", name)
	}
	return &value.Boolean{Value: true}, nil
}
