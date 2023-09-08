package function

import (
	"time"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Testing_fixed_time_lookup_Name = "testing.fixed_time"

var Testing_fixed_time_lookup_ArgumentTypes = []value.Type{value.StringType}

func Testing_fixed_time_lookup_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Testing_fixed_time_lookup_Name, 1, args)
	}
	return nil
}

const expectedTimeFormat = "2006-01-02 15:04:05"

func Testing_fixed_time(
	ctx *context.Context,
	args ...value.Value,
) (value.Value, error) {

	if err := Testing_fixed_time_lookup_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	switch args[0].Type() {
	case value.IntegerType:
		v := value.Unwrap[*value.Integer](args[0])
		t := time.Unix(v.Value, 0)
		ctx.FixedTime = &t
	case value.TimeType:
		t := value.Unwrap[*value.Time](args[0]).Value
		ctx.FixedTime = &t
	case value.StringType:
		fixed := value.Unwrap[*value.String](args[0]).Value
		ft, err := time.Parse(expectedTimeFormat, fixed)
		if err != nil {
			return value.Null, errors.NewTestingError("Invalid time format: %s", err)
		}
		ctx.FixedTime = &ft
	default:
		return value.Null, errors.NewTestingError(
			"First argument of %s must be INTEGER or TIME or STRING type, %s provided",
			Testing_fixed_time_lookup_Name,
			args[0].Type(),
		)
	}
	return value.Null, nil
}
