package function

import (
	"maps"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter"
	"github.com/ysugimoto/falco/interpreter/context"
	ifn "github.com/ysugimoto/falco/interpreter/function"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/tester/shared"
)

const allScope = context.AnyScope

type Definiions struct {
	Tables      map[string]*ast.TableDeclaration
	Backends    map[string]*value.Backend
	Acls        map[string]*value.Acl
	Subroutines map[string]*ast.SubroutineDeclaration
}

type Functions map[string]*ifn.Function

func TestingFunctions(i *interpreter.Interpreter, defs *Definiions, c *shared.Counter, cv *shared.Coverage) Functions {
	functions := Functions{}
	maps.Copy(functions, testingFunctions(i, defs))
	maps.Copy(functions, assertionFunctions(i, c))
	if cv != nil {
		maps.Copy(functions, coverageFunctions(cv))
	}
	return functions
}

func coverageFunctions(c *shared.Coverage) Functions {
	return Functions{
		"coverage.subroutine": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				return Coverage(c, shared.CoverageTypeSubroutine, args...)
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"coverage.statement": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				return Coverage(c, shared.CoverageTypeStatement, args...)
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"coverage.branch": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				return Coverage(c, shared.CoverageTypeBranch, args...)
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
	}
}

// nolint: funlen,gocognit
func testingFunctions(i *interpreter.Interpreter, defs *Definiions) Functions {
	return Functions{
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
		"testing.fixed_time": {Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				return Testing_fixed_time(ctx, unwrapped...)
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"testing.override_host": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				return Testing_override_host(ctx, unwrapped...)
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
		"testing.table_set": {
			Scope:            allScope,
			Call:             Testing_table_set,
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"testing.table_merge": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				return Testing_table_merge(ctx, defs, args...)
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"testing.mock": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				return Testing_mock(ctx, defs, args...)
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"testing.restore_mock": {
			Scope:            allScope,
			Call:             Testing_restore_mock,
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"testing.restore_all_mocks": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				return Testing_restore_all_mocks(ctx)
			},
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"testing.inject_variable": {
			Scope:            allScope,
			Call:             Testing_inject_variable,
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"testing.get_env": {
			Scope:            allScope,
			Call:             Testing_get_env,
			CanStatementCall: false,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"testing.fixed_access_rate": {
			Scope:            allScope,
			Call:             Testing_fixed_access_rate,
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
		"testing.set_backend_health": {
			Scope:            allScope,
			Call:             Testing_set_backend_health,
			CanStatementCall: true,
			IsIdentArgument: func(i int) bool {
				return false
			},
		},
	}
}

// nolint: funlen,gocognit
func assertionFunctions(i *interpreter.Interpreter, c *shared.Counter) Functions {
	return Functions{
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
		"assert.subroutine_called": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_subroutine_called(ctx, unwrapped...)
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
		"assert.not_subroutine_called": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_not_subroutine_called(ctx, unwrapped...)
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
		"assert.restart": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_restart(ctx, i, unwrapped...)
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
		"assert.state": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_state(ctx, i, unwrapped...)
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
		"assert.not_state": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_not_state(ctx, i, unwrapped...)
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
		"assert.error": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_error(ctx, i, unwrapped...)
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
		"assert.not_error": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_not_error(ctx, i, unwrapped...)
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
		"assert.is_json": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_is_json(ctx, unwrapped...)
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
		"assert.is_notset": {
			Scope: allScope,
			Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
				unwrapped, err := unwrapIdentArguments(i, args)
				if err != nil {
					return value.Null, errors.WithStack(err)
				}
				v, err := Assert_is_notset(ctx, unwrapped...)
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
		"assert.equal_fold": {
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
