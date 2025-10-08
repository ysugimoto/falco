package shared

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestBase64Encode(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{
			input:  "Καλώς ορίσατε",
			expect: "zprOsc67z47PgiDOv8+Bzq/Pg86xz4TOtQ==",
		},
	}

	for _, tt := range tests {
		v := Base64Encode(tt.input)
		if diff := cmp.Diff(tt.expect, v); diff != "" {
			t.Errorf("Return value unmach, diff=%s", diff)
		}
	}
}

func TestBase64UrlEncode(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{
			input:  "Καλώς ορίσατε",
			expect: "zprOsc67z47PgiDOv8-Bzq_Pg86xz4TOtQ==",
		},
	}

	for _, tt := range tests {
		v := Base64UrlEncode(tt.input)
		if diff := cmp.Diff(tt.expect, v); diff != "" {
			t.Errorf("Return value unmach, diff=%s", diff)
		}
	}
}

func TestBase64UrlEncodeNoPad(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{
			input:  "Καλώς ορίσατε",
			expect: "zprOsc67z47PgiDOv8-Bzq_Pg86xz4TOtQ",
		},
	}

	for _, tt := range tests {
		v := Base64UrlEncodeNoPad(tt.input)
		if diff := cmp.Diff(tt.expect, v); diff != "" {
			t.Errorf("Return value unmach, diff=%s", diff)
		}
	}
}

func TestBase64Decode(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{
			input:  "zprOsc67z47PgiDOv8+Bzq/Pg86xz4TOtQ==",
			expect: "Καλώς ορίσατε",
		},
		{
			input:  "c29tZSBkYXRhIHdpdGggACBhbmQg77u/",
			expect: "some data with ",
		},
		{
			input:  "QU&|*#()JDRA==",
			expect: "ABCD",
		},
		{
			input:  "QU&==|*#()JDRA==",
			expect: "A",
		},
		{
			input:  "QU&=|*#()JDRA==",
			expect: "A",
		},
		{
			input:  "YWJjZB==",
			expect: "abcd",
		},
		{
			input:  "aGVsbG8=0",
			expect: "hello",
		},
	}

	for _, tt := range tests {
		v := Base64Decode(tt.input)
		if diff := cmp.Diff(tt.expect, v); diff != "" {
			t.Errorf("Return value unmach, diff=%s", diff)
		}
	}
}

func TestBase64UrlDecode(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{
			input:  "zprOsc67z47PgiDOv8-Bzq_Pg86xz4TOtQ==",
			expect: "Καλώς ορίσατε",
		},
		{
			input:  "c29tZSBkYXRhIHdpdGggACBhbmQg77u/",
			expect: "some data with ",
		},
		{
			input:  "QU&|*#()JDRA==",
			expect: "ABCD",
		},
		{
			input:  "QU&==|*#()JDRA==",
			expect: "A",
		},
		{
			input:  "QU&=|*#()JDRA==",
			expect: "A",
		},
		{
			input:  "YWJjZB==",
			expect: "abcd",
		},
		{
			input:  "aGVsbG8=0",
			expect: "hello",
		},
	}

	for _, tt := range tests {
		v := Base64UrlDecode(tt.input)
		if diff := cmp.Diff(tt.expect, v); diff != "" {
			t.Errorf("Return value unmach, diff=%s", diff)
		}
	}
}

func TestBase64UrlDecodeNoPad(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{
			input:  "zprOsc67z47PgiDOv8-Bzq_Pg86xz4TOtQ",
			expect: "Καλώς ορίσατε",
		},
		{
			input:  "c29tZSBkYXRhIHdpdGggACBhbmQg77u/",
			expect: "some data with ",
		},
		{
			input:  "QU&|*#()JDRA==",
			expect: "ABCD",
		},
		{
			input:  "QU&==|*#()JDRA==",
			expect: "ABCD",
		},
		{
			input:  "QU&=|*#()JDRA==",
			expect: "ABCD",
		},
		{
			input:  "YWJjZB==",
			expect: "abcd",
		},
		{
			input:  "aGVsbG8=0",
			expect: "hello4",
		},
	}

	for _, tt := range tests {
		v := Base64UrlDecodeNoPad(tt.input)
		if diff := cmp.Diff(tt.expect, v); diff != "" {
			t.Errorf("Return value unmach, diff=%s", diff)
		}
	}
}
