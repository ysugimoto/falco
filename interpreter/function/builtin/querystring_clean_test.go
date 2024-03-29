// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of querystring.clean
// Arguments may be:
// - STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/query-string/querystring-clean/
func Test_Querystring_clean(t *testing.T) {
	tests := []struct {
		input  *value.String
		expect *value.String
	}{
		{input: &value.String{Value: "/path?name=value&&=value-only&name-only"}, expect: &value.String{Value: "/path?name=value&name-only"}},
		{input: &value.String{Value: "/path?"}, expect: &value.String{Value: "/path"}},
	}

	for i, tt := range tests {
		ret, err := Querystring_clean(&context.Context{}, tt.input)
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
