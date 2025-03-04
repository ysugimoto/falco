package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_equal_Name = "assert.equal"

func Assert_equal_Validate(args []value.Value) error {
	if len(args) < 2 || len(args) > 3 {
		return errors.ArgumentNotInRange(Assert_equal_Name, 2, 3, args)
	}
	if len(args) == 3 {
		if args[2].Type() != value.StringType {
			return errors.TypeMismatch(Assert_equal_Name, 3, value.StringType, args[2].Type())
		}
	}
	return nil
}

func Assert_equal(ctx *context.Context, args ...value.Value) (value.Value, error) {
	if err := Assert_equal_Validate(args); err != nil {
		return nil, errors.NewTestingError("%s", err.Error())
	}

	// assert.equal is alias for assert.strict_equal
	return assert_strict_equal(args...)
}
