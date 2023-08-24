package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_not_equal_lookup_Name = "assert"

func Assert_not_equal_lookup_Validate(args []value.Value) error {
	if len(args) < 2 || len(args) > 3 {
		return errors.ArgumentNotInRange(Assert_not_equal_lookup_Name, 2, 3, args)
	}
	if len(args) == 3 {
		if args[2].Type() != value.StringType {
			return errors.TypeMismatch(Assert_not_equal_lookup_Name, 3, value.StringType, args[2].Type())
		}
	}
	return nil
}

func Assert_not_equal(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Inverse assert.equal result
	ret, err := Assert_equal(ctx, args...)
	if ret == nil {
		return nil, err
	}

	v := value.Unwrap[*value.Boolean](ret)
	v.Value = !v.Value
	return v, err
}
