package builtin

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_Waf_jsDecode(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"\\x41", "A"},
		{"\\u0041", "A"},
		{"\\n", "\n"},
		{"\\t", "\t"},
		{"\\r", "\r"},
		{"hello", "hello"},
		{"", ""},
	}

	for _, tt := range tests {
		ret, err := Waf_jsDecode(
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
