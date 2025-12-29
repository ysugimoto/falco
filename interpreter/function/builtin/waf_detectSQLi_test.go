package builtin

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_Waf_detectSQLi(t *testing.T) {
	tests := []struct {
		input        string
		expectDetect bool
	}{
		{"1' OR '1'='1", true},
		{"1; DROP TABLE users--", true},
		{"' UNION SELECT * FROM users--", true},
		{"hello world", false},
		{"normal query parameter", false},
		{"", false},
	}

	for _, tt := range tests {
		ctx := &context.Context{
			RegexMatchedValues: make(map[string]*value.String),
		}
		ret, err := Waf_detectSQLi(ctx, &value.String{Value: tt.input})
		if err != nil {
			t.Errorf("Unexpected error for input %q: %s", tt.input, err)
			continue
		}
		if ret.Type() != value.BooleanType {
			t.Errorf("Unexpected return type, expect=BOOL, got=%s", ret.Type())
			continue
		}
		v := value.Unwrap[*value.Boolean](ret)
		if v.Value != tt.expectDetect {
			t.Errorf("input=%q: expect=%v, got=%v", tt.input, tt.expectDetect, v.Value)
		}
		if tt.expectDetect {
			if _, ok := ctx.RegexMatchedValues["0"]; !ok {
				t.Errorf("input=%q: expected re.group.0 to be set on detection", tt.input)
			}
		}
	}
}
