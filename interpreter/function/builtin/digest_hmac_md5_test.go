// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of digest.hmac_md5
// Arguments may be:
// - STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/cryptographic/digest-hmac-md5/
func Test_Digest_hmac_md5(t *testing.T) {
	ret, err := Digest_hmac_md5(
		&context.Context{},
		&value.String{Value: "secret"},
		&value.String{Value: "input"},
	)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if ret.Type() != value.StringType {
		t.Errorf("Unexpected return type, expect=STRING, got=%s", ret.Type())
	}
	v := value.Unwrap[*value.String](ret)
	expect := "bf8d470185ab817f3c92bb5cef1fd7d5"
	if v.Value != expect {
		t.Errorf("return value unmach, expect=%s, got=%s", expect, v.Value)
	}
}