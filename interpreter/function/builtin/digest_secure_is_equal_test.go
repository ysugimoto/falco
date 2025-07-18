// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of digest.secure_is_equal
// Arguments may be:
// - STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/cryptographic/digest-secure-is-equal/
func Test_Digest_secure_is_equal(t *testing.T) {

	tests := []struct {
		s1     string
		s2     string
		expect bool
	}{
		{
			s1:     "thisiscomparestring",
			s2:     "thisiscomparestring",
			expect: true,
		},
		{
			s1:     "thisiscomparestring",
			s2:     "thisiscomparestrin",
			expect: false,
		},
	}

	for _, tt := range tests {
		ret, err := Digest_secure_is_equal(
			&context.Context{},
			&value.String{Value: tt.s1},
			&value.String{Value: tt.s2},
		)

		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}
		if ret.Type() != value.BooleanType {
			t.Errorf("Unexpected return type, expect=BOOL, got=%s", ret.Type())
		}
		v := value.Unwrap[*value.Boolean](ret)
		if v.Value != tt.expect {
			t.Errorf("return value unmatch, expect=%t, got=%t", tt.expect, v.Value)
		}
	}
}
