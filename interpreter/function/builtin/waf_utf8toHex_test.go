package builtin

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_Waf_utf8toHex(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"A", "A"},           // printable ASCII stays as-is
		{"abc", "abc"},       // printable ASCII stays as-is
		{" ", " "},           // space (0x20) is printable, passes through
		{"\x00", "%u000000"}, // null byte
		{"日", "%u0065e5"},    // Unicode U+65E5
		{"", ""},
		{"%", "%u000025"},    // percent sign gets encoded
		{"\x1f", "%u00001f"}, // control char below space
		{"\x7f", "%u00007f"}, // DEL char
	}

	for _, tt := range tests {
		ret, err := Waf_utf8toHex(
			&context.Context{},
			&value.String{Value: tt.input},
		)
		if err != nil {
			t.Errorf("Unexpected error for input %q: %s", tt.input, err)
			continue
		}
		if ret.Type() != value.StringType {
			t.Errorf("Unexpected return type, expect=STRING, got=%s", ret.Type())
			continue
		}
		v := value.Unwrap[*value.String](ret)
		if v.Value != tt.expect {
			t.Errorf("input=%q: expect=%q, got=%q", tt.input, tt.expect, v.Value)
		}
	}
}
