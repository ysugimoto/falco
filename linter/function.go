package linter

import (
	"fmt"
	"slices"
	"unicode/utf8"

	"github.com/ysugimoto/falco/v2/ast"
	"github.com/ysugimoto/falco/v2/linter/context"
	"github.com/ysugimoto/falco/v2/linter/types"
	"github.com/ysugimoto/falco/v2/token"
)

type functionMeta struct {
	name      string
	token     token.Token
	arguments []ast.Expression
	meta      *ast.Meta
}

var implicitCoersionTable = map[types.Type][]types.Type{
	types.TimeType:  {types.StringType},
	types.RTimeType: {types.TimeType, types.StringType},
	types.IPType:    {types.StringType},
	types.IDType:    {types.StringType},
	types.StringType: {
		types.StringType, types.ReqBackendType, types.BackendType, types.IntegerType, types.FloatType, types.BoolType,
		types.IDType, types.RTimeType, types.IPType, types.TimeType,
	},
}

func (l *Linter) lintFunctionArguments(fn *context.BuiltinFunction, calledFn functionMeta, ctx *context.Context) types.Type {
	// lint empty arguments
	if len(fn.Arguments) == 0 {
		if len(calledFn.arguments) > 0 {
			err := &LintError{
				Severity: ERROR,
				Token:    calledFn.token,
				Message: fmt.Sprintf(
					"function %s has 0 arity, but %d arguments provided",
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
		if slices.Contains(a, types.StringListType) {
			// For variadic StringListType variants, the caller must provide
			// at least as many arguments as the non-variadic prefix
			// (i.e. all positions before the StringListType slot).
			nonVariadic := slices.Index(a, types.StringListType)
			if len(calledFn.arguments) >= nonVariadic {
				argTypes = a
				break
			}
		} else if len(a) == len(calledFn.arguments) {
			argTypes = a
			break
		}
	}
	if len(argTypes) == 0 {
		l.Error(FunctionArgumentMismatch(
			calledFn.meta, calledFn.name,
			len(fn.Arguments), len(calledFn.arguments),
		).Match(FUNCTION_ARGUMENTS).Ref(fn.Reference))
		return fn.Return
	}

	for i, v := range argTypes {
		if v == types.StringListType {
			// Variadic arguments linting, at least one argument must be provided and must be a StringType
			if i == len(calledFn.arguments) {
				err := &LintError{
					Severity: ERROR,
					Token:    calledFn.token,
					Message: fmt.Sprintf(
						"Function %s requires at least one argument",
						calledFn.name,
					),
				}
				l.Error(err.Match(FUNCTION_ARGUMENTS).Ref(fn.Reference))
				return fn.Return
			}

			for j := i; j < len(calledFn.arguments); j++ {
				arg := l.lint(calledFn.arguments[j], ctx)
				if !expectType(arg, types.StringType) {
					l.Error(FunctionArgumentTypeMismatch(
						calledFn.meta, calledFn.name, j+1, types.StringType, arg,
					).Match(FUNCTION_ARGUMENT_TYPE).Ref(fn.Reference))
				}
			}
		} else {
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
	}

	// Special cases
	if calledFn.name == "regsub" || calledFn.name == "regsuball" {
		if !isTypeLiteral(calledFn.arguments[1]) {
			l.Error(&LintError{
				Severity: ERROR,
				Token:    calledFn.arguments[1].GetMeta().Token,
				Message:  "Regex patterns must be string literals.",
			})
		}
	}
	if calledFn.name == "utf8.translate" {
		l.lintTranslationSets(calledFn, fn.Reference)
	}

	return fn.Return
}

// Fastly builds the translation table of utf8.translate when it compiles the
// VCL, so both character sets must be string literals.
func (l *Linter) lintTranslationSets(calledFn functionMeta, reference string) {
	raise := func(arg ast.Expression, format string, args ...any) {
		err := &LintError{
			Severity: ERROR,
			Token:    arg.GetMeta().Token,
			Message:  fmt.Sprintf(format, args...),
		}
		l.Error(err.Match(FUNCTION_ARGUMENTS).Ref(reference))
	}

	var counts [2]int
	for i, name := range []string{"set1", "set2"} {
		arg := calledFn.arguments[i+1]
		str, ok := arg.(*ast.String)
		if !ok {
			raise(arg, "The %s argument of utf8.translate must be a string literal.", name)
			return
		}
		if str.Value == "" {
			raise(arg, "Characters required in %s", name)
			return
		}
		counts[i] = utf8.RuneCountInString(str.Value)
	}

	if counts[1] > counts[0] {
		raise(
			calledFn.arguments[2],
			"Excess characters in set2: Expected %d or fewer, got %d", counts[0], counts[1],
		)
	}
}
