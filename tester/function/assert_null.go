package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_null_lookup_Name = "assert"

func Assert_null_lookup_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Assert_null_lookup_Name, 1, args)
	}
	return nil
}

func Assert_null(ctx *context.Context, args ...value.Value) (value.Value, error) {
	if err := Assert_null_lookup_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	switch args[0].Type() {
	case value.StringType:
		v := value.Unwrap[*value.String](args[0])
		return assert(v.IsNotSet, true, "value is not null")
	case value.IpType:
		v := value.Unwrap[*value.IP](args[0])
		return assert(v.IsNotSet, true, "value is not null")
	default:
		return assert(args[0].String(), "NULL", "value is not null")
	}
}
