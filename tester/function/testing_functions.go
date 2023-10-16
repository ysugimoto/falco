package function

import (
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter"
	"github.com/ysugimoto/falco/interpreter/context"
	ifn "github.com/ysugimoto/falco/interpreter/function"
	"github.com/ysugimoto/falco/interpreter/value"
)

const allScope = context.AnyScope

type Counter interface {
	Pass()
	Fail()
}

// nolint: funlen,gocognit
func TestingFunctions(i *interpreter.Interpreter, c Counter) map[string]*ifn.Function {
	return map[string]*ifn.Function{
		// Special testing function of "testing.call_subrouting"
		// We need to interpret subroutine statement in this function
		// so pass *interpreter.Interpreter pointer to the function
		"testing.call_subroutine": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				v, err := Testing_call_subroutine(ctx, i, args...)
				if err != nil {
					return value.Null, err
				}
				ctx.ReturnState = value.Unwrap[*value.String](v)
				return value.Null, nil
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"testing.fixed_time": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Testing_fixed_time(ctx, unwrapped...)
				if err != nil {
					c.Fail()
				} else {
					c.Pass()
				}
				return v, err
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"testing.inspect": {
			Scope: allScope,
			// On this function, we don't need to unwrap ident
			// because ident value should be looked up as predefined variables
			Call:             Testing_inspect,
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"assert": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert(ctx, unwrapped...)
				if err != nil {
					c.Fail()
				} else {
					c.Pass()
				}
				return v, err
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"assert.true": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_true(ctx, unwrapped...)
				if err != nil {
					c.Fail()
				} else {
					c.Pass()
				}
				return v, err
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"assert.false": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_false(ctx, unwrapped...)
				if err != nil {
					c.Fail()
				} else {
					c.Pass()
				}
				return v, err
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"assert.equal": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_equal(ctx, unwrapped...)
				if err != nil {
					c.Fail()
				} else {
					c.Pass()
				}
				return v, err
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"assert.not_equal": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_not_equal(ctx, unwrapped...)
				if err != nil {
					c.Fail()
				} else {
					c.Pass()
				}
				return v, err
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"assert.strict_equal": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_strict_equal(ctx, unwrapped...)
				if err != nil {
					c.Fail()
				} else {
					c.Pass()
				}
				return v, err
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"assert.not_strict_equal": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_not_strict_equal(ctx, unwrapped...)
				if err != nil {
					c.Fail()
				} else {
					c.Pass()
				}
				return v, err
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"assert.match": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_match(ctx, unwrapped...)
				if err != nil {
					c.Fail()
				} else {
					c.Pass()
				}
				return v, err
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"assert.not_match": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_not_match(ctx, unwrapped...)
				if err != nil {
					c.Fail()
				} else {
					c.Pass()
				}
				return v, err
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"assert.contains": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_contains(ctx, unwrapped...)
				if err != nil {
					c.Fail()
				} else {
					c.Pass()
				}
				return v, err
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"assert.not_contains": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_not_contains(ctx, unwrapped...)
				if err != nil {
					c.Fail()
				} else {
					c.Pass()
				}
				return v, err
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"assert.starts_with": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_starts_with(ctx, unwrapped...)
				if err != nil {
					c.Fail()
				} else {
					c.Pass()
				}
				return v, err
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"assert.ends_with": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_ends_with(ctx, unwrapped...)
				if err != nil {
					c.Fail()
				} else {
					c.Pass()
				}
				return v, err
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
	}
}

func unwrapIdentArguments(ip *interpreter.Interpreter, args []value.Value) ([]value.Value, error) {
	for i := range args {
		if args[i].Type() != value.IdentType {
			continue
		}
		ident := value.Unwrap[*value.Ident](args[i])
		v, err := ip.IdentValue(ident.Value, false)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		args[i] = v
	}

	return args, nil
}
