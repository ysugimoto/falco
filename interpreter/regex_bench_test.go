package interpreter

import (
	"testing"

	"github.com/ysugimoto/falco/v2/interpreter/context"
	"github.com/ysugimoto/falco/v2/interpreter/function/builtin"
	"github.com/ysugimoto/falco/v2/interpreter/operator"
	"github.com/ysugimoto/falco/v2/interpreter/value"
)

// Library-agnostic benchmarks for comparing regex engines: they go through
// the interpreter entry points, which compile the pattern on every call.

func BenchmarkRegexOperator(b *testing.B) {
	ctx := context.New()
	left := &value.String{Value: "/api/v2/users/abc"}
	right := &value.String{Value: `^/api/v[0-9]+/(users|items)/([^/]+)$`, Literal: true}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := operator.Regex(ctx, left, right); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRegsuball(b *testing.B) {
	ctx := context.New()
	input := &value.String{Value: "a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8"}
	pattern := &value.String{Value: `([a-z])=([0-9])`, Literal: true}
	repl := &value.String{Value: `\2:\1`}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := builtin.Regsuball(ctx, input, pattern, repl); err != nil {
			b.Fatal(err)
		}
	}
}
