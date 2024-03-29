// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of boltsort.sort
// Arguments may be:
// - STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/query-string/boltsort-sort/
func Test_Boltsort_sort(t *testing.T) {

	ret, err := Boltsort_sort(
		&context.Context{},
		&value.String{Value: "/foo?b=1&a=2&c=3"},
	)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if ret.Type() != value.StringType {
		t.Errorf("Unexpected type returned, expect=%s, got=%s", value.StringType, ret.Type())
	}
	v := value.Unwrap[*value.String](ret)
	if v.Value != "/foo?a=2&b=1&c=3" {
		t.Errorf("Unexpected value returned, expect=/foo?a=2&b=1&c=3, got=%s", v.Value)
	}
}
