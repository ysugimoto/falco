package builtin

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_Waf_validateByteRange(t *testing.T) {
	tests := []struct {
		rangeSpec string
		input     string
		expect    bool
	}{
		{"97-122", "abc", true},          // a-z
		{"97-122", "ABC", false},         // A-Z not in range
		{"65-90,97-122", "ABCabc", true}, // A-Z and a-z
		{"48-57", "12345", true},         // 0-9
		{"48-57", "123a5", false},        // contains 'a'
		{"0-255", "anything", true},      // full range
		{"97-122", "", false},            // empty input returns false
	}

	for _, tt := range tests {
		ret, err := Waf_validateByteRange(
			&context.Context{},
			&value.String{Value: tt.rangeSpec},
			&value.String{Value: tt.input},
		)
		if err != nil {
			t.Errorf("Unexpected error for range=%q input=%q: %s", tt.rangeSpec, tt.input, err)
			continue
		}
		if ret.Type() != value.BooleanType {
			t.Errorf("Unexpected return type, expect=BOOL, got=%s", ret.Type())
			continue
		}
		v := value.Unwrap[*value.Boolean](ret)
		if v.Value != tt.expect {
			t.Errorf("range=%q input=%q: expect=%v, got=%v", tt.rangeSpec, tt.input, tt.expect, v.Value)
		}
	}
}
