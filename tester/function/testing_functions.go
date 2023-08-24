package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	ifn "github.com/ysugimoto/falco/interpreter/function"
	"github.com/ysugimoto/falco/interpreter/value"
)

const allScope = context.RecvScope | context.HashScope | context.HitScope | context.MissScope | context.PassScope | context.FetchScope | context.ErrorScope | context.DeliverScope | context.LogScope

var TestingFunctions = map[string]*ifn.Function{
	"assert": {
		Scope: allScope,
		Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
			return Assert(ctx, args...)
		},
		CanStatementCall: true,
		IsIdentArgument: func(i int) bool {
			return false
		},
	},
	"assert.null": {
		Scope: allScope,
		Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
			return Assert_null(ctx, args...)
		},
		CanStatementCall: true,
		IsIdentArgument: func(i int) bool {
			return false
		},
	},
	"assert.true": {
		Scope: allScope,
		Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
			return Assert_true(ctx, args...)
		},
		CanStatementCall: true,
		IsIdentArgument: func(i int) bool {
			return false
		},
	},
	"assert.false": {
		Scope: allScope,
		Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
			return Assert_false(ctx, args...)
		},
		CanStatementCall: true,
		IsIdentArgument: func(i int) bool {
			return false
		},
	},
	"assert.equal": {
		Scope: allScope,
		Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
			return Assert_equal(ctx, args...)
		},
		CanStatementCall: true,
		IsIdentArgument: func(i int) bool {
			return false
		},
	},
	"assert.not_equal": {
		Scope: allScope,
		Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
			return Assert_not_equal(ctx, args...)
		},
		CanStatementCall: true,
		IsIdentArgument: func(i int) bool {
			return false
		},
	},
	"assert.strict_equal": {
		Scope: allScope,
		Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
			return Assert_strict_equal(ctx, args...)
		},
		CanStatementCall: true,
		IsIdentArgument: func(i int) bool {
			return false
		},
	},
	"assert.not_strict_equal": {
		Scope: allScope,
		Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
			return Assert_not_strict_equal(ctx, args...)
		},
		CanStatementCall: true,
		IsIdentArgument: func(i int) bool {
			return false
		},
	},
	"assert.match": {
		Scope: allScope,
		Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
			return Assert_match(ctx, args...)
		},
		CanStatementCall: true,
		IsIdentArgument: func(i int) bool {
			return false
		},
	},
	"assert.not_match": {
		Scope: allScope,
		Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
			return Assert_not_match(ctx, args...)
		},
		CanStatementCall: true,
		IsIdentArgument: func(i int) bool {
			return false
		},
	},
	"assert.contains": {
		Scope: allScope,
		Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
			return Assert_contains(ctx, args...)
		},
		CanStatementCall: true,
		IsIdentArgument: func(i int) bool {
			return false
		},
	},
	"assert.not_contains": {
		Scope: allScope,
		Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
			return Assert_not_contains(ctx, args...)
		},
		CanStatementCall: true,
		IsIdentArgument: func(i int) bool {
			return false
		},
	},
	"assert.starts_with": {
		Scope: allScope,
		Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
			return Assert_starts_with(ctx, args...)
		},
		CanStatementCall: true,
		IsIdentArgument: func(i int) bool {
			return false
		},
	},
	"assert.ends_with": {
		Scope: allScope,
		Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) {
			return Assert_ends_with(ctx, args...)
		},
		CanStatementCall: true,
		IsIdentArgument: func(i int) bool {
			return false
		},
	},
}
