package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_Name = "assert"

var Assert_ArgumentTypes = []value.Type{value.BooleanType}

func Assert_Validate(args []value.Value) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.ArgumentNotInRange(Assert_Name, 1, 2, args)
	}

	if len(args) == 2 {
		if args[1].Type() != value.StringType {
			return errors.TypeMismatch(Assert_Name, 2, value.StringType, args[1].Type())
		}
	}
	return nil
}

func Assert(ctx *context.Context, args ...value.Value) (value.Value, error) {
	if err := Assert_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	// Check custom message
	var message string
	if len(args) == 3 {
		message = value.Unwrap[*value.String](args[2]).Value
	} else {
		message = "Expression value should be truthy"
	}

	switch args[0].Type() {
	case value.StringType:
		v := value.Unwrap[*value.String](args[0])
		return assert_not(v, v.Value, "", message)
	case value.BooleanType:
		v := value.Unwrap[*value.Boolean](args[0])
		return assert(v, v.Value, true, message)
	default:
		return &value.Boolean{}, errors.NewAssertionError(
			args[0],
			"Type Mismatch: %s could not assert as truthy value",
			args[0].Type(),
		)
	}
}
