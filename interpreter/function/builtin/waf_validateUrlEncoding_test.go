package builtin

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_Waf_validateUrlEncoding(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		{"hello", true},
		{"hello%20world", true},
		{"%2F", true},
		{"%2f", true},
		{"%", false},
		{"%2", false},
		{"%2G", false},
		{"%GG", false},
		{"hello%ZZworld", false},
		{"", true},
	}

	for _, tt := range tests {
		ret, err := Waf_validateUrlEncoding(
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
