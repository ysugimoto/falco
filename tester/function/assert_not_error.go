package function

import (
	"github.com/ysugimoto/falco/interpreter"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_not_error_Name = "assert.not_error"

var Assert_not_error_ArgumentTypes = []value.Type{value.IntegerType}

func Assert_not_error_Validate(args []value.Value) error {
	if len(args) > 1 {
		return errors.ArgumentNotInRange(Assert_not_error_Name, 0, 1, args)
	}

	return nil
}

func Assert_not_error(
	ctx *context.Context,
	i *interpreter.Interpreter,
	args ...value.Value,
) (value.Value, error) {

	if err := Assert_not_error_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	// extract arguments
	var message string
	if len(args) == 1 {
		message = value.Unwrap[*value.String](args[0]).Value
	}

	// Check state doesn't move to ERROR internally
	if i.TestingState == interpreter.ERROR {
		if message == "" {
			return &value.Boolean{}, errors.NewAssertionError(
				&value.String{Value: i.TestingState.String()},
				"State should not move to ERROR",
			)
		}
		return &value.Boolean{}, errors.NewAssertionError(
			&value.String{Value: i.TestingState.String()},
			message,
		)
	}

	return &value.Boolean{Value: true}, nil
}
