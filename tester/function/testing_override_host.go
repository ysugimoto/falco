package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Testing_override_host_Name = "testing.override_host"

func Testing_override_host_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Testing_override_host_Name, 1, args)
	}
	return nil
}

func Testing_override_host(
	ctx *context.Context,
	args ...value.Value,
) (value.Value, error) {

	if err := Testing_override_host_Validate(args); err != nil {
		return nil, errors.NewTestingError("%s", err.Error())
	}

	switch args[0].Type() {
	case value.StringType:
		override := value.Unwrap[*value.String](args[0]).Value
		ctx.OriginalHost = override
		if ctx.Request != nil {
			ctx.Request.Header.Set("Host", override)
			ctx.Request.Assign("Host")
		}
	default:
		return value.Null, errors.NewTestingError(
			"First argument of %s must be STRING type, %s provided",
			Testing_override_host_Name,
			args[0].Type(),
		)
	}
	return value.Null, nil
}
