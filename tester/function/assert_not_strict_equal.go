package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_not_strict_equal_Name = "assert.not_strict_equal"

func Assert_not_strict_equal_Validate(args []value.Value) error {
	if len(args) < 2 || len(args) > 3 {
		return errors.ArgumentNotInRange(Assert_not_strict_equal_Name, 2, 3, args)
	}
	if len(args) == 3 {
		if args[2].Type() != value.StringType {
			return errors.TypeMismatch(Assert_not_strict_equal_Name, 3, value.StringType, args[2].Type())
		}
	}
	return nil
}

func Assert_not_strict_equal(ctx *context.Context, args ...value.Value) (value.Value, error) {
	if err := Assert_not_strict_equal_Validate(args); err != nil {
		return nil, errors.NewTestingError("%s", err.Error())
	}

	return assert_not_strict_equal(args...)
}

func assert_not_strict_equal(args ...value.Value) (value.Value, error) {
	// Check custom message
	var message string
	if len(args) == 3 {
		message = value.Unwrap[*value.String](args[2]).Value
	}

	actual, expect := args[0], args[1]
	if expect.Type() != actual.Type() {
		if message == "" {
			return &value.Boolean{}, errors.NewAssertionError(
				actual,
				"Type Mismatch: expect=%s but actual=%s",
				expect.Type(),
				actual.Type(),
			)
		}
		return &value.Boolean{}, errors.NewAssertionError(actual, "%s", message)
	}

	return assert_not(actual, actual.String(), expect.String(), message)
}
