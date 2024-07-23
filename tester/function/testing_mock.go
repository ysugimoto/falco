package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Testing_mock_Name = "testing.mock"

var Testing_mock_ArgumentTypes = []value.Type{value.StringType, value.StringType}

func Testing_mock_Validate(args []value.Value) error {
	if len(args) != 2 {
		return errors.ArgumentNotEnough(Testing_mock_Name, 2, args)
	}

	for i := range Testing_mock_ArgumentTypes {
		if args[i].Type() != Testing_mock_ArgumentTypes[i] {
			return errors.TypeMismatch(
				Testing_mock_Name, i+1, Testing_mock_ArgumentTypes[i], args[i].Type(),
			)
		}
	}
	return nil
}

func Testing_mock(
	ctx *context.Context,
	defs *Definiions,
	args ...value.Value,
) (value.Value, error) {

	if err := Testing_mock_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	from := value.Unwrap[*value.String](args[0]).Value
	to := value.Unwrap[*value.String](args[1]).Value

	if _, ok := Testing_mock_Fastly_reserved[from]; ok {
		return value.Null, errors.NewTestingError("Cannot mock Fastly reserved subroutine %s", from)
	}

	// Check subroutine existence
	mockFrom, ok := ctx.Subroutines[from]
	if !ok {
		if mockFrom, ok = ctx.SubroutineFunctions[from]; !ok {
			return value.Null, errors.NewTestingError("subroutine %s is not declared in VCL", from)
		}
	}

	mockTo, ok := defs.Subroutines[to]
	if !ok {
		return value.Null, errors.NewTestingError("mock subroutine %s is not declared in testing VCL", to)
	}

	// Check functional subroutine
	if mockFrom.ReturnType != nil {
		if mockTo.ReturnType == nil {
			return value.Null, errors.NewTestingError(
				"%s is functional subroutine but mock target %s is not functional", from, to,
			)
		}

		// Return type must match between original and mock target
		if mockFrom.ReturnType.Value != mockTo.ReturnType.Value {
			return value.Null, errors.NewTestingError(
				"mocking subroutine return type mismatch, original is %s, mock target is %s",
				mockFrom.ReturnType.Value,
				mockTo.ReturnType.Value,
			)
		}

		ctx.MockedFunctioncalSubroutines[from] = mockTo
		return value.Null, nil
	}

	if mockTo.ReturnType != nil {
		return value.Null, errors.NewTestingError(
			"%s is subroutine but mock target %s is functional subroutine", from, to,
		)
	}

	ctx.MockedSubroutines[from] = mockTo
	return value.Null, nil
}

var Testing_mock_Fastly_reserved = map[string]struct{}{
	"vcl_recv":    {},
	"vcl_hash":    {},
	"vcl_hit":     {},
	"vcl_miss":    {},
	"vcl_pass":    {},
	"vcl_fetch":   {},
	"vcl_error":   {},
	"vcl_deliver": {},
	"vcl_log":     {},
}
