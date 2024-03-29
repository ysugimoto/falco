// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of std.replace_prefix
// Arguments may be:
// - STRING, STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/strings/std-replace-prefix/
func Test_Std_replace_prefix(t *testing.T) {
	tests := []struct {
		input   string
		target  string
		replace string
		expect  string
	}{
		{input: "abcabc", target: "ab", replace: "", expect: "cabc"},
		{input: "0xABCD1234", target: "0x", replace: "", expect: "ABCD1234"},
	}

	for i, tt := range tests {
		ret, err := Std_replace_prefix(
			&context.Context{},
			&value.String{Value: tt.input},
			&value.String{Value: tt.target},
			&value.String{Value: tt.replace},
		)
		if err != nil {
			t.Errorf("[%d] Unexpected error: %s", i, err)
		}
		if ret.Type() != value.StringType {
			t.Errorf("[%d] Unexpected return type, expect=STRING, got=%s", i, ret.Type())
		}
		v := value.Unwrap[*value.String](ret)
		if diff := cmp.Diff(tt.expect, v.Value); diff != "" {
			t.Errorf("[%d] Return value unmatch, diff=%s", i, diff)
		}
	}
}
