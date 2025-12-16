package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Testing_restore_mock_Name = "testing.restore_mock"

func Testing_restore_mock_Validate(args []value.Value) error {
	if len(args) == 0 {
		return errors.ArgumentAtLeast(Testing_restore_mock_Name, 1)
	}

	for i := range args {
		if args[i].Type() != value.StringType {
			return errors.TypeMismatch(
				Testing_restore_mock_Name, i+1, value.StringType, args[i].Type(),
			)
		}
	}

	return nil
}

func Testing_restore_mock(
	ctx *context.Context,
	args ...value.Value,
) (value.Value, error) {

	if err := Testing_restore_mock_Validate(args); err != nil {
		return nil, errors.NewTestingError("%s", err.Error())
	}

	for i := range args {
		name := value.Unwrap[*value.String](args[i]).Value
		if _, ok := ctx.MockedSubroutines[name]; ok {
			delete(ctx.MockedSubroutines, name)
			continue
		}
		if _, ok := ctx.MockedFunctioncalSubroutines[name]; ok {
			delete(ctx.MockedFunctioncalSubroutines, name)
			continue
		}
		return value.Null, errors.NewTestingError("subroutine %s is not mocked", name)
	}
	return value.Null, nil
}
