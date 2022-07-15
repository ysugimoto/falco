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
		if len(a) == len(calledFn.arguments) {
			argTypes = a
			break
		}
	}
	if len(argTypes) == 0 {
		l.Error(FunctionArgumentMismatch(
			calledFn.meta, calledFn.name,
			len(fn.Arguments), len(calledFn.arguments),
		).Match(FUNCTION_ARGUMENTS).Ref(fn.Reference))
	}

	for i, v := range argTypes {
		arg := l.lint(calledFn.arguments[i], ctx)

		switch v {
		case types.TimeType:
			// fuzzy type check: some builtin function expects TIME type,
			// then actual argument type could be STRING because VCL TIME type could be parsed from STRING.
			if !expectType(arg, types.TimeType, types.StringType) {
				l.Error(FunctionArgumentTypeMismatch(
					calledFn.meta, calledFn.name, i+1, v, arg,
				).Match(FUNCTION_ARGUMENT_TYPE).Ref(fn.Reference))
			}
			continue
		case types.RTimeType:
			// fuzzy type check: some builtin function expects RTIME type,
			// then actual argument type could be STRING because VCL TIME type could be parsed from STRING.
			if !expectType(arg, types.RTimeType, types.TimeType, types.StringType) {
				l.Error(FunctionArgumentTypeMismatch(
					calledFn.meta, calledFn.name, i+1, v, arg,
				).Match(FUNCTION_ARGUMENT_TYPE).Ref(fn.Reference))
			}
			continue
		case types.IPType:
			// fuzzy type check: some builtin function expects IP type,
			// then actual argument type could be STRING because VCL TIME type could be parsed from STRING.
			if !expectType(arg, types.IPType, types.StringType) {
				l.Error(FunctionArgumentTypeMismatch(
					calledFn.meta, calledFn.name, i+1, v, arg,
				).Match(FUNCTION_ARGUMENT_TYPE).Ref(fn.Reference))
			}
		default:
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
