package function

import (
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Testing_call_subroutine_Name = "testing.call_subroutine"

// CallResult distinguishes functional subroutine return values from
// scoped subroutine state names so the caller can branch correctly
// without inspecting the concrete value type.
type CallResult struct {
	Value        value.Value
	IsFunctional bool
}

func Testing_call_subroutine_Validate(args []value.Value) error {
	if len(args) < 1 {
		return errors.ArgumentNotEnough(Testing_call_subroutine_Name, 1, args)
	}
	if args[0].Type() != value.StringType {
		return errors.TypeMismatch(
			Testing_call_subroutine_Name,
			1,
			value.StringType,
			args[0].Type(),
		)
	}
	return nil
}

// resolveSubroutine looks up a subroutine by name in ctx, checking mocked
// overrides first. It returns the declaration and whether it is a functional
// (return-typed) subroutine.
func resolveSubroutine(
	ctx *context.Context,
	name string,
) (*ast.SubroutineDeclaration, bool) {

	// Functional subroutine – check mock override first
	if mocked, ok := ctx.MockedFunctioncalSubroutines[name]; ok {
		return mocked, true
	}
	if sub, ok := ctx.SubroutineFunctions[name]; ok {
		return sub, true
	}
	// Scoped subroutine – check mock override first
	if mocked, ok := ctx.MockedSubroutines[name]; ok {
		return mocked, false
	}
	if sub, ok := ctx.Subroutines[name]; ok {
		return sub, false
	}
	return nil, false
}

func Testing_call_subroutine(
	ctx *context.Context,
	i *interpreter.Interpreter,
	args ...value.Value,
) (*CallResult, error) {

	if err := Testing_call_subroutine_Validate(args); err != nil {
		return nil, errors.NewTestingError("%s", err.Error())
	}

	name := value.Unwrap[*value.String](args[0]).Value
	subArgs := args[1:]

	sub, isFunctional := resolveSubroutine(ctx, name)
	if sub == nil {
		return nil, errors.NewTestingError(
			"subroutine %s is not defined in VCL", name,
		)
	}

	if len(subArgs) != len(sub.Parameters) {
		return nil, errors.NewTestingError(
			"%s expects %d argument(s), got %d",
			name,
			len(sub.Parameters),
			len(subArgs),
		)
	}

	if isFunctional {
		retVal, _, err := i.ProcessFunctionSubroutine(
			sub, interpreter.DebugPass, subArgs,
		)
		ctx.TestingReturnValue = retVal
		if err != nil {
			return nil, errors.NewTestingError("%s", err.Error())
		}
		return &CallResult{
			Value:        retVal,
			IsFunctional: true,
		}, nil
	}

	state, err := i.ProcessSubroutine(sub, interpreter.DebugPass, subArgs)
	if err != nil {
		return nil, errors.NewTestingError("%s", err.Error())
	}
	i.TestingState = state
	return &CallResult{
		Value:        &value.String{Value: string(state)},
		IsFunctional: false,
	}, nil
}
