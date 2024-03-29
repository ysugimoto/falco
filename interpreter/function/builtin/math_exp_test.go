// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of math.exp
// Arguments may be:
// - FLOAT
// Reference: https://developer.fastly.com/reference/vcl/functions/math-logexp/math-exp/
func Test_Math_exp(t *testing.T) {
	tests := []struct {
		input  *value.Float
		expect *value.Float
		err    *value.String
	}{
		{input: &value.Float{IsNAN: true}, expect: &value.Float{IsNAN: true}, err: nil},
		{input: &value.Float{IsNegativeInf: true}, expect: &value.Float{IsNegativeInf: true}, err: nil},
		{input: &value.Float{IsPositiveInf: true}, expect: &value.Float{IsPositiveInf: true}, err: nil},
		{input: &value.Float{Value: math.MaxFloat64}, expect: &value.Float{Value: math.Inf(1)}, err: nil},
		{input: &value.Float{Value: -math.MaxFloat64}, expect: &value.Float{Value: 0}, err: nil},
		{input: &value.Float{Value: 0.5}, expect: &value.Float{Value: 1.6487212707001282}, err: nil},
	}

	for i, tt := range tests {
		ret, err := Math_exp(&context.Context{}, tt.input)
		if err != nil {
			t.Errorf("[%d] Unexpected error: %s", i, err)
		}
		if ret.Type() != value.FloatType {
			t.Errorf("[%d] Unexpected return type, expect=FLOAT, got=%s", i, ret.Type())
		}
		v := value.Unwrap[*value.Float](ret)
		if diff := cmp.Diff(v, tt.expect); diff != "" {
			t.Errorf("[%d] Return value unmatch, diff: %s", i, diff)
		}
	}
}
