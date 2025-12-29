package builtin

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_Waf_validateUtf8Encoding(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		{"hello", true},
		{"日本語", true},
		{"", true},
		{"\xc3\x28", false},         // invalid 2-byte sequence
		{"\xe2\x28\xa1", false},     // invalid 3-byte sequence
		{"\xf0\x28\x8c\xbc", false}, // invalid 4-byte sequence
		{"abc\x80def", false},       // continuation byte without start
	}

	for _, tt := range tests {
		ret, err := Waf_validateUtf8Encoding(
			&context.Context{},
			&value.String{Value: tt.input},
		)
		if err != nil {
			t.Errorf("Unexpected error for input %q: %s", tt.input, err)
			continue
		}
		if ret.Type() != value.BooleanType {
			t.Errorf("Unexpected return type, expect=BOOL, got=%s", ret.Type())
			continue
		}
		v := value.Unwrap[*value.Boolean](ret)
		if v.Value != tt.expect {
			t.Errorf("input=%q: expect=%v, got=%v", tt.input, tt.expect, v.Value)
		}
	}
}
