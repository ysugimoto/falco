// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of querystring.regfilter_except
// Arguments may be:
// - STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/query-string/querystring-regfilter-except/
func Test_Querystring_regfilter_except(t *testing.T) {
	tests := []struct {
		input  *value.String
		expect *value.String
	}{
		{input: &value.String{Value: "/path?a=b"}, expect: &value.String{Value: "/path"}},
		{input: &value.String{Value: "/path?a=b&utm_source=foo"}, expect: &value.String{Value: "/path?utm_source=foo"}},
	}

	for i, tt := range tests {
		ret, err := Querystring_regfilter_except(
			&context.Context{},
			tt.input,
			&value.String{Value: "utm_*"},
		)
		if err != nil {
			t.Errorf("[%d] Unexpected error: %s", i, err)
		}
		if ret.Type() != value.StringType {
			t.Errorf("[%d] Unexpected return type, expect=STRING, got=%s", i, ret.Type())
		}
		v := value.Unwrap[*value.String](ret)
		if diff := cmp.Diff(v, tt.expect); diff != "" {
			t.Errorf("[%d] Return value unmatch, diff: %s", i, diff)
		}
	}
}
