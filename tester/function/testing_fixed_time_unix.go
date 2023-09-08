package function

import (
	"time"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Testing_fixed_time_unix_lookup_Name = "testing.fixed_time_unix"

func Testing_fixed_time_unix_lookup_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Testing_fixed_time_unix_lookup_Name, 1, args)
	}
	return nil
}

func Testing_fixed_time_unix(
	ctx *context.Context,
	args ...value.Value,
) (value.Value, error) {

	switch args[0].Type() {
	case value.IntegerType:
		v := value.Unwrap[*value.Integer](args[0])
		t := time.Unix(v.Value, 0)
		ctx.FixedTime = &t
	case value.TimeType:
		t := value.Unwrap[*value.Time](args[0]).Value
		ctx.FixedTime = &t
	default:
		return value.Null, errors.NewTestingError(
			"First argument of %s must be INTEGER or TIME type, %s provided",
			Testing_fixed_time_unix_lookup_Name,
			args[0].Type(),
		)
	}
	return value.Null, nil
}
