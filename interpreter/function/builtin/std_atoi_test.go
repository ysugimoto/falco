// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of std.atoi
// Arguments may be:
// - STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/strings/std-atoi/
func Test_Std_atoi(t *testing.T) {
	tests := []struct {
		input  string
		expect int64
	}{
		{input: "21.95", expect: 21},
		{input: "-100", expect: -100},
		{input: "0", expect: 0},
		{input: "", expect: 0},
	}

	for i, tt := range tests {
		ret, err := Std_atoi(
			&context.Context{},
			&value.String{Value: tt.input},
		)
		if err != nil {
			t.Errorf("[%d] Unexpected error: %s", i, err)
		}
		if ret.Type() != value.IntegerType {
			t.Errorf("[%d] Unexpected return type, expect=INTEGER, got=%s", i, ret.Type())
		}
		v := value.Unwrap[*value.Integer](ret)
		if diff := cmp.Diff(tt.expect, v.Value); diff != "" {
			t.Errorf("[%d] Return value unmatch, diff=%s", i, diff)
		}
	}
}
