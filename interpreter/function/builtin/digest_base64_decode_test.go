// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of digest.base64_decode
// Arguments may be:
// - STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/cryptographic/digest-base64-decode/
func Test_Digest_base64_decode(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "Fastly example",
			input:  "zprOsc67z47PgiDOv8+Bzq/Pg86xz4TOtQ==",
			expect: "Καλώς ορίσατε",
		},
		{
			name:   "Includes nullbyte",
			input:  "c29tZSBkYXRhIHdpdGggACBhbmQg77u/",
			expect: "some data with ",
		},
		{
			name:   "Skip invalid characters",
			input:  "QU&|*#()JDRA==",
			expect: "ABCD",
		},
		{
			name:   "Stop at padding sign",
			input:  "QU&==|*#()JDRA==",
			expect: "A",
		},
		{
			name:   "Stop at single equal sign",
			input:  "QU&=|*#()JDRA==",
			expect: "A",
		},
		{
			name:   "Treat padding - keep padding characters",
			input:  "YWJjZB==",
			expect: "abcd",
		},
		{
			// https://github.com/ysugimoto/falco/issues/431
			name:   "issue-431",
			input:  "Zm9vYmFyVGVzdAo=",
			expect: "foobarTest\n",
		},
	}

	for _, tt := range tests {
		ret, err := Digest_base64_decode(
			&context.Context{},
			&value.String{Value: tt.input},
		)

		if err != nil {
			t.Errorf("[%s] Unexpected error: %s", tt.name, err)
		}
		if ret.Type() != value.StringType {
			t.Errorf("[%s] Unexpected return type, expect=STRING, got=%s", tt.name, ret.Type())
		}
		v := value.Unwrap[*value.String](ret)
		if v.Value != tt.expect {
			t.Errorf("[%s] return value unmatch, expect=%s, got=%s", tt.name, tt.expect, v.Value)
		}
	}
}
