package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_subroutine_called_Name = "assert.subroutine_called"

func Assert_subroutine_called_Validate(args []value.Value) error {
	if len(args) < 1 || len(args) > 3 {
		return errors.ArgumentNotInRange(Assert_subroutine_called_Name, 1, 3, args)
	}

	if args[0].Type() != value.StringType {
		return errors.TypeMismatch(Assert_subroutine_called_Name, 1, value.StringType, args[0].Type())
	}
	return nil
}

func Assert_subroutine_called(ctx *context.Context, args ...value.Value) (value.Value, error) {
	if err := Assert_subroutine_called_Validate(args); err != nil {
		return nil, errors.NewTestingError("%s", err.Error())
	}

	name := value.Unwrap[*value.String](args[0]).Value

	// Check custom message
	var message string
	var times int64 = 1
	var prural string
	switch len(args) {
	case 3: // (name, times, message)
		times = value.Unwrap[*value.Integer](args[1]).Value
		if times > 1 {
			prural = "s"
		}
		message = value.Unwrap[*value.String](args[2]).Value
	case 2: // (name, times or message)
		switch args[1].Type() {
		case value.IntegerType:
			times = value.Unwrap[*value.Integer](args[1]).Value
			if times > 1 {
				prural = "s"
			}
		case value.StringType:
			message = value.Unwrap[*value.String](args[1]).Value
		default:
			return &value.Boolean{}, errors.NewTestingError(
				"%s: 2nd argument must be INTEGER or STRING, %s provided",
				Assert_subroutine_called_Name, args[1].Type(),
			)
		}
	}

	call, ok := ctx.SubroutineCalls[name]
	if !ok {
		if message != "" {
			return &value.Boolean{}, errors.NewAssertionError(args[0], "%s", message)
		}
		return &value.Boolean{}, errors.NewAssertionError(args[0], "Subroutine %s is not called", name)
	}
	if int64(call) != times {
		var cp string
		if call > 1 {
			cp = "s"
		}
		if message != "" {
			return &value.Boolean{}, errors.NewAssertionError(
				&value.Integer{Value: int64(call)},
				"%s", message,
			)
		}
		return &value.Boolean{}, errors.NewAssertionError(
			&value.Integer{Value: int64(call)},
			"Subroutine %s should be called %d time%s but actual called %d time%s",
			name, times, prural, call, cp,
		)
	}
	return &value.Boolean{Value: true}, nil
}
