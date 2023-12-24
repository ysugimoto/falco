package function

import (
	"github.com/ysugimoto/falco/interpreter"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_error_Name = "assert.error"

var Assert_error_ArgumentTypes = []value.Type{value.IntegerType}

func Assert_error_Validate(args []value.Value) error {
	if len(args) < 1 || len(args) > 3 {
		return errors.ArgumentNotInRange(Assert_error_Name, 1, 3, args)
	}

	for i := range Assert_error_ArgumentTypes {
		if args[i].Type() != Assert_error_ArgumentTypes[i] {
			return errors.TypeMismatch(Assert_error_Name, i+1, Assert_error_ArgumentTypes[i], args[i].Type())
		}
	}

	return nil
}

func Assert_error(
	ctx *context.Context,
	i *interpreter.Interpreter,
	args ...value.Value,
) (value.Value, error) {

	if err := Assert_error_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	// extract arguments
	var message string
	if len(args) == 3 {
		message = value.Unwrap[*value.String](args[2]).Value
	}

	// First, check state moves to ERROR internally
	if i.TestingState != interpreter.ERROR {
		if message == "" {
			return &value.Boolean{}, errors.NewAssertionError(
				&value.String{Value: i.TestingState.String()},
				"State does not move to ERROR, current state is %s",
				i.TestingState.String(),
			)
		}
		return &value.Boolean{}, errors.NewAssertionError(
			&value.String{Value: i.TestingState.String()},
			message,
		)
	}

	// status code check
	code := value.Unwrap[*value.Integer](args[0]).Value
	if ctx.ObjectStatus.Value != code {
		if message == "" {
			return &value.Boolean{}, errors.NewAssertionError(
				ctx.ObjectStatus,
				"Error response code mismatch: expects %d, got %d",
				code, ctx.ObjectStatus.Value,
			)
		}
		return &value.Boolean{}, errors.NewAssertionError(
			ctx.ObjectStatus,
			message,
		)
	}

	// response string check
	if len(args) > 1 {
		response := value.Unwrap[*value.String](args[1]).Value
		if ctx.ObjectResponse.Value != response {
			if message == "" {
				return &value.Boolean{}, errors.NewAssertionError(
					ctx.ObjectResponse,
					"Error response text mismatch: expects %s, got %s",
					response, ctx.ObjectResponse.Value,
				)
			}
			return &value.Boolean{}, errors.NewAssertionError(
				ctx.ObjectResponse,
				message,
			)
		}
	}

	return &value.Boolean{Value: true}, nil
}
