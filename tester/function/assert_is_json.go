package function

import (
	"encoding/json"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_is_json_Name = "testing.get_log"

func Assert_is_json_Validate(args []value.Value) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.ArgumentNotInRange(Assert_is_json_Name, 1, 2, args)
	}

	if args[0].Type() != value.StringType {
		return errors.TypeMismatch(
			Assert_is_json_Name, 1, value.StringType, args[0].Type(),
		)
	}

	if len(args) == 2 {
		if args[1].Type() != value.StringType {
			return errors.TypeMismatch(Assert_ends_with_Name, 2, value.StringType, args[1].Type())
		}
	}
	return nil
}

func Assert_is_json(
	ctx *context.Context,
	args ...value.Value,
) (value.Value, error) {

	if err := Assert_is_json_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	// Check custom message
	var message string
	if len(args) == 2 {
		message = value.Unwrap[*value.String](args[2]).Value
	} else {
		message = "Value should be JSON"
	}

	msg := value.Unwrap[*value.String](args[0])
	valid := &value.Boolean{Value: json.Valid([]byte(msg.Value))}
	if !valid.Value {
		return valid, errors.NewAssertionError(valid, message)
	}
	return valid, nil
}
