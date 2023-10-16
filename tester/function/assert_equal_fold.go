package function

import (
	"strings"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_equal_fold_Name = "assert.equal_fold"

func Assert_equal_fold_Validate(args []value.Value) error {
	if len(args) < 2 || len(args) > 3 {
		return errors.ArgumentNotInRange(Assert_equal_fold_Name, 2, 3, args)
	}
	if len(args) == 3 {
		if args[2].Type() != value.StringType {
			return errors.TypeMismatch(Assert_equal_fold_Name, 3, value.StringType, args[2].Type())
		}
	}
	return nil
}

func Assert_equal_fold(ctx *context.Context, args ...value.Value) (value.Value, error) {
	if err := Assert_equal_fold_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	return assert_equal_fold(args...)
}

func assert_equal_fold(args ...value.Value) (value.Value, error) {
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
		return &value.Boolean{}, errors.NewAssertionError(actual, message)
	}

	ok := &value.Boolean{Value: strings.EqualFold(actual.String(), expect.String())}
	if !ok.Value {
		if message != "" {
			return ok, errors.NewAssertionError(actual, message)
		}
		return ok, errors.NewAssertionError(actual,
			"Assertion error: expect=%v, actual=%v", expect, actual)
	}
	return ok, nil
}
