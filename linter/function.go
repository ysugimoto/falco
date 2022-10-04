package linter

import (
	"fmt"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/context"
	"github.com/ysugimoto/falco/token"
	"github.com/ysugimoto/falco/types"
)

type functionMeta struct {
	name      string
	token     token.Token
	arguments []ast.Expression
	meta      *ast.Meta
}

var implicitCoersionTable = map[types.Type][]types.Type{
	types.TimeType:   {types.StringType},
	types.RTimeType:  {types.TimeType, types.StringType},
	types.IPType:     {types.StringType},
	types.IDType:     {types.StringType},
	types.StringType: {types.StringType, types.ReqBackendType, types.IntegerType, types.FloatType, types.BoolType, types.IDType, types.RTimeType},
}

func (l *Linter) lintFunctionArguments(fn *context.BuiltinFunction, calledFn functionMeta, ctx *context.Context) types.Type {
	// lint empty arguments
	if len(fn.Arguments) == 0 {
		if len(calledFn.arguments) > 0 {
			err := &LintError{
				Severity: ERROR,
				Token:    calledFn.token,
				Message: fmt.Sprintf(
					"function %s wants no arguments but provides %d argument",
					calledFn.name, len(calledFn.arguments),
				),
			}
			l.Error(err.Match(FUNCTION_ARGUMENTS).Ref(fn.Reference))
			return types.NeverType
		}
		return fn.Return
	}

	var argTypes []types.Type
	for _, a := range fn.Arguments {
		// Special case of variadic arguments of types.StringListType,
		// We do not compare argument length, just lint with "all argument types are STRING".
		if a[0] == types.StringListType || len(a) == len(calledFn.arguments) {
			argTypes = a
			break
		}
	}
	if len(argTypes) == 0 {
		l.Error(FunctionArgumentMismatch(
			calledFn.meta, calledFn.name,
			len(fn.Arguments), len(calledFn.arguments),
		).Match(FUNCTION_ARGUMENTS).Ref(fn.Reference))
	} else if argTypes[0] == types.StringListType {
		// Variadic arguments linting, at least one argument must be provided and must be a StringType
		if len(calledFn.arguments) == 0 {
			err := &LintError{
				Severity: ERROR,
				Token:    calledFn.token,
				Message: fmt.Sprintf(
					"function %s requires at least one argument",
					calledFn.name,
				),
			}
			l.Error(err.Match(FUNCTION_ARGUMENTS).Ref(fn.Reference))
			return fn.Return
		}

		for i, arg := range calledFn.arguments {
			a := l.lint(arg, ctx)
			if !expectType(a, types.StringType) {
				l.Error(FunctionArgumentTypeMismatch(
					calledFn.meta, calledFn.name, i+1, types.StringType, a,
				).Match(FUNCTION_ARGUMENT_TYPE).Ref(fn.Reference))
			}
		}
		return fn.Return
	}

	for i, v := range argTypes {
		arg := l.lint(calledFn.arguments[i], ctx)

		if t, ok := implicitCoersionTable[v]; ok {
			if !expectType(arg, append(t, v)...) {
				l.Error(FunctionArgumentTypeMismatch(
					calledFn.meta, calledFn.name, i+1, v, arg,
				).Match(FUNCTION_ARGUMENT_TYPE).Ref(fn.Reference))
			}
		} else {
			// Otherwise, strict type check
			if v != arg {
				l.Error(FunctionArgumentTypeMismatch(
					calledFn.meta, calledFn.name, i+1, v, arg,
				).Match(FUNCTION_ARGUMENT_TYPE).Ref(fn.Reference))
			}
		}
	}

	return fn.Return
}
