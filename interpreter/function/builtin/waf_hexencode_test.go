package builtin

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_Waf_hexencode(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"abc", "616263"},
		{"ABC", "414243"},
		{"123", "313233"},
		{"", ""},
		{"\x00\x01\x02", "000102"},
		{"hello world", "68656c6c6f20776f726c64"},
	}

	for _, tt := range tests {
		ret, err := Waf_hexencode(
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
