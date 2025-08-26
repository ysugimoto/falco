package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Testing_fixed_access_rate_Name = "testing.fixed_access_rate"

func Testing_fixed_access_rate_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Testing_fixed_access_rate_Name, 1, args)
	}
	return nil
}

func Testing_fixed_access_rate(
	ctx *context.Context,
	args ...value.Value,
) (value.Value, error) {

	if err := Testing_fixed_access_rate_Validate(args); err != nil {
		return nil, errors.NewTestingError("%s", err.Error())
	}

	switch args[0].Type() {
	case value.IntegerType:
		v := float64(value.Unwrap[*value.Integer](args[0]).Value)
		ctx.FixedAccessRate = &v
	case value.FloatType:
		v := value.Unwrap[*value.Float](args[0]).Value
		ctx.FixedAccessRate = &v
	default:
		return value.Null, errors.NewTestingError(
			"First argument of %s must be INTEGER or FLOAT type, %s provided",
			Testing_fixed_access_rate_Name,
			args[0].Type(),
		)
	}
	return value.Null, nil
}
