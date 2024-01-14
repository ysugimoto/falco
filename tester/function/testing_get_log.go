package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/process"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Testing_get_log_Name = "testing.get_log"

func Testing_get_log_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Testing_get_log_Name, 1, args)
	}

	if args[0].Type() != value.IntegerType {
		return errors.TypeMismatch(
			Testing_get_log_Name, 1, value.IntegerType, args[0].Type(),
		)
	}
	return nil
}

func Testing_get_log(
	ctx *context.Context,
	proc *process.Process,
	args ...value.Value,
) (value.Value, error) {

	if err := Testing_get_log_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	offset := int(value.Unwrap[*value.Integer](args[0]).Value)

	if offset >= len(proc.Logs) {
		return value.Null, nil
	}

	return &value.String{Value: proc.Logs[offset].Message}, nil
}
