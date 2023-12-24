package function

import (
	"strings"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/process"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Testing_get_log_Name = "testing.get_log"

var Testing_get_log_ArgumentTypes = []value.Type{value.StringType, value.IntegerType}

func Testing_get_log_Validate(args []value.Value) error {
	if len(args) != 2 {
		return errors.ArgumentNotEnough(Testing_get_log_Name, 2, args)
	}

	for i := range Testing_get_log_ArgumentTypes {
		if args[i].Type() != Testing_get_log_ArgumentTypes[i] {
			return errors.TypeMismatch(
				Testing_get_log_Name, i+1, Testing_get_log_ArgumentTypes[i], args[i].Type(),
			)
		}
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

	state := strings.ToUpper(value.Unwrap[*value.String](args[0]).Value)
	offset := int(value.Unwrap[*value.Integer](args[1]).Value)
	var i int

	for _, l := range proc.Logs {
		if l.Scope == state {
			if i == offset {
				return &value.String{Value: l.Message}, nil
			}
			i += 1
		}
	}

	return value.Null, nil
}
