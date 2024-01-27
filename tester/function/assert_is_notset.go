package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_is_notset_Name = "assert.is_notset"

func Assert_is_notset_Validate(args []value.Value) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.ArgumentNotInRange(Assert_is_notset_Name, 1, 2, args)
	}

	return nil
}

func Assert_is_notset(ctx *context.Context, args ...value.Value) (value.Value, error) {
	if err := Assert_is_notset_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	// Check custom message
	var message string
	if len(args) == 3 {
		message = value.GetString(args[2]).String()
	} else {
		message = "Value isn't NotSet"
	}

	switch args[0].Type() {
	case value.StringType:
		v := value.GetString(args[0])
		return assert(v, v.IsNotSet, true, message)
	case value.IpType:
		v := value.Unwrap[*value.IP](args[0])
		return assert(v, v.IsNotSet, true, message)
	default:
		return &value.Boolean{}, errors.NewTestingError(
			"Assertion type mismatch, %s type must be STRING or IP type which have NotSet status",
			args[0].Type(),
		)
	}
}
