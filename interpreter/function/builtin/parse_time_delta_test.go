// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of parse_time_delta
// Arguments may be:
// - STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/date-and-time/parse-time-delta/
func Test_Parse_time_delta(t *testing.T) {
	tests := []struct {
		input  *value.String
		expect *value.Integer
	}{
		{input: &value.String{Value: "2d"}, expect: &value.Integer{Value: 172800}},
		{input: &value.String{Value: "2D"}, expect: &value.Integer{Value: 172800}},
		{input: &value.String{Value: "3h"}, expect: &value.Integer{Value: 10800}},
		{input: &value.String{Value: "3H"}, expect: &value.Integer{Value: 10800}},
		{input: &value.String{Value: "1m"}, expect: &value.Integer{Value: 60}},
		{input: &value.String{Value: "1M"}, expect: &value.Integer{Value: 60}},
		{input: &value.String{Value: "10s"}, expect: &value.Integer{Value: 10}},
		{input: &value.String{Value: "10S"}, expect: &value.Integer{Value: 10}},
	}

	for i, tt := range tests {
		ret, err := Parse_time_delta(&context.Context{}, tt.input)
		if err != nil {
			t.Errorf("[%d] Unexpected error: %s", i, err)
		}
		if ret.Type() != value.IntegerType {
			t.Errorf("[%d] Unexpected return type, expect=INTEGER, got=%s", i, ret.Type())
		}
		v := value.Unwrap[*value.Integer](ret)
		if diff := cmp.Diff(v, tt.expect); diff != "" {
			t.Errorf("[%d] Return value unmatch, diff: %s", i, diff)
		}
	}
}
