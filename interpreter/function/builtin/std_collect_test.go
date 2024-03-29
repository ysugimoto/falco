// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of std.collect
// Arguments may be:
// - ID
// - ID, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/miscellaneous/std-collect/
func Test_Std_collect(t *testing.T) {
	tests := []struct {
		input  string
		expect int64
	}{
		{input: "req.headers", expect: 1},
	}

	for i, tt := range tests {
		req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
		if err != nil {
			t.Errorf("[%d] Unexpected request creation error: %s", i, err)
		}
		req.Header.Set("Foo", "bar")
		ret, err := Std_count(
			&context.Context{Request: req},
			&value.Ident{Value: tt.input},
		)
		if err != nil {
			t.Errorf("[%d] Unexpected error: %s", i, err)
		}
		if ret.Type() != value.IntegerType {
			t.Errorf("[%d] Unexpected return type, expect=INTEGER, got=%s", i, ret.Type())
		}
		v := value.Unwrap[*value.Integer](ret)
		if diff := cmp.Diff(tt.expect, v.Value); diff != "" {
			t.Errorf("[%d] Return value unmatch, diff=%s", i, diff)
		}
	}
}
