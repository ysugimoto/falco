package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_false_Name = "assert.false"

func Assert_false_Validate(args []value.Value) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.ArgumentNotInRange(Assert_false_Name, 1, 2, args)
	}

	if len(args) == 2 {
		if args[1].Type() != value.StringType {
			return errors.TypeMismatch(Assert_false_Name, 2, value.StringType, args[1].Type())
		}
	}
	return nil
}

func Assert_false(ctx *context.Context, args ...value.Value) (value.Value, error) {
	if err := Assert_false_Validate(args); err != nil {
		return nil, errors.NewTestingError("%s", err.Error())
	}

	// Check custom message
	var message string
	if len(args) == 2 {
		message = value.Unwrap[*value.String](args[1]).Value
	} else {
		message = "Value should be false"
	}

	switch args[0].Type() {
	case value.BooleanType:
		v := value.Unwrap[*value.Boolean](args[0])
		return assert(v, v.Value, false, message)
	default:
		return &value.Boolean{}, errors.NewTestingError(
			"Assertion type mismatch, %s type is not BOOLEAN type",
			args[0].Type(),
		)
	}
}
