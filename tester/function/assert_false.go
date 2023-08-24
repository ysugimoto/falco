package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_false_lookup_Name = "assert"

func Assert_false_lookup_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Assert_false_lookup_Name, 1, args)
	}
	return nil
}

func Assert_false(ctx *context.Context, args ...value.Value) (value.Value, error) {
	if err := Assert_false_lookup_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	switch args[0].Type() {
	case value.BooleanType:
		v := value.Unwrap[*value.Boolean](args[0])
		return assert(v.Value, false, "")
	default:
		return &value.Boolean{}, errors.NewTestingError(
			"Assertion type mismatch, %s type is not BOOLEAN type",
			args[0].Type(),
		)
	}
}
