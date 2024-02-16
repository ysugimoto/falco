package function

import (
	"github.com/ysugimoto/falco/interpreter"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Testing_call_subroutine_Name = "assert"

var Testing_call_subroutine_ArgumentTypes = []value.Type{value.StringType}

func Testing_call_subroutine_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Testing_call_subroutine_Name, 1, args)
	}
	for i := range args {
		if args[i].Type() != Testing_call_subroutine_ArgumentTypes[i] {
			return errors.TypeMismatch(
				Testing_call_subroutine_Name,
				i+1,
				Testing_call_subroutine_ArgumentTypes[i],
				args[i].Type(),
			)
		}
	}
	return nil
}

func Testing_call_subroutine(
	ctx *context.Context,
	i *interpreter.Interpreter,
	args ...value.Value,
) (value.Value, error) {

	if err := Testing_call_subroutine_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	var state interpreter.State
	var err error
	name := value.Unwrap[*value.String](args[0]).Value

	// Functional subroutine
	if sub, ok := ctx.SubroutineFunctions[name]; ok {
		_, state, err = i.ProcessFunctionSubroutine(sub, interpreter.DebugPass)
		// Scoped subroutine
	} else if sub, ok := ctx.Subroutines[name]; ok {
		state, err = i.ProcessSubroutine(sub, interpreter.DebugPass)
		i.TestingState = state
	} else {
		return value.Null, errors.NewTestingError("subroutine %s is not defined in VCL", name)
	}
	if err != nil {
		return value.Null, errors.NewTestingError(err.Error())
	}
	return &value.String{Value: string(state)}, nil
}
