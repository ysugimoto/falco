// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of digest.hash_crc32
// Arguments may be:
// - STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/cryptographic/digest-hash-crc32/
func Test_Digest_hash_crc32(t *testing.T) {
	ret, err := Digest_hash_crc32(
		&context.Context{},
		&value.String{Value: "123456789"},
	)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if ret.Type() != value.StringType {
		t.Errorf("Unexpected return type, expect=STRING, got=%s", ret.Type())
	}
	v := value.Unwrap[*value.String](ret)
	expect := "181989fc"
	if v.Value != expect {
		t.Errorf("return value unmatch, expect=%s, got=%s", expect, v.Value)
	}
}
