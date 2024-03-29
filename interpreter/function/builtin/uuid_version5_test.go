// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of uuid.version5
// Arguments may be:
// - STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/uuid/uuid-version5/
func Test_Uuid_version5(t *testing.T) {
	tests := []struct {
		namespace string
		input     string
		expect    string
	}{
		{
			namespace: "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
			input:     "www.fastly.com",
			expect:    "86573da0-058f-5871-a5b7-f3cb33447360",
		},
	}

	for i, tt := range tests {
		ret, err := Uuid_version5(
			&context.Context{},
			&value.String{Value: tt.namespace},
			&value.String{Value: tt.input},
		)
		if err != nil {
			t.Errorf("[%d] Unexpected error: %s", i, err)
		}
		if ret.Type() != value.StringType {
			t.Errorf("[%d] Unexpected return type, expect=STRING, got=%s", i, ret.Type())
		}
		v := value.Unwrap[*value.String](ret)
		if diff := cmp.Diff(tt.expect, v.Value); diff != "" {
			t.Errorf("[%d] Return value unmatch, diff=%s", i, diff)
		}
	}
}
