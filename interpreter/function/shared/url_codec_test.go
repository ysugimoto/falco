package shared

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestUrlEncode(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{
			input:  "%00",
			expect: "",
		},
		{
			input:  "ab%00c",
			expect: "ab",
		},
		{
			input:  "あ",
			expect: "%E3%81%82",
		},
		{
			input:  "𠮷😯",
			expect: "%F0%A0%AE%B7%F0%9F%98%AF",
		},
		{
			input:  "%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F",
			expect: "%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F",
		},
		{
			input:  "%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F",
			expect: "%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F",
		},
		{
			input:  " !\"#$%&'()*+,-./",
			expect: "%20%21%22%23%24%25%26%27%28%29%2A%2B%2C-.%2F",
		},
		{
			input:  "0123456789:;<=>?",
			expect: "0123456789%3A%3B%3C%3D%3E%3F",
		},
		{
			input:  "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_",
			expect: "%40ABCDEFGHIJKLMNOPQRSTUVWXYZ%5B%5C%5D%5E_",
		},
		{
			input:  "`abcdefghijklmnopqrstuvwxyz{|}~",
			expect: "%60abcdefghijklmnopqrstuvwxyz%7B%7C%7D~",
		},
		{
			input:  "%7F",
			expect: "%7F",
		},
		{
			input:  "hello world",
			expect: "hello%20world",
		},
	}

	for i, tt := range tests {
		ret, err := UrlEncode(tt.input)
		if err != nil {
			t.Errorf("[%d] Unexpected error: %s", i, err)
		}
		if diff := cmp.Diff(tt.expect, ret); diff != "" {
			t.Errorf("[%d] Return value unmatch, diff=%s", i, diff)
		}
	}
}

func TestUrlDecode(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{
			input:  "",
			expect: "",
		},
		{
			input:  "ab",
			expect: "ab",
		},
		{
			input:  "%E3%81%82",
			expect: "あ",
		},
		{
			input:  "%F0%A0%AE%B7%F0%9F%98%AF",
			expect: "𠮷😯",
		},
		{
			input:  "%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F",
			expect: string([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}),
		},
		{
			input:  "%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F",
			expect: string([]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}),
		},
		{
			input:  "%20%21%22%23%24%25%26%27%28%29%2A%2B%2C-.%2F",
			expect: ` !"#$%&'()*+,-./`,
		},
		{
			input:  "0123456789%3A%3B%3C%3D%3E%3F",
			expect: "0123456789:;<=>?",
		},
		{
			input:  "%40ABCDEFGHIJKLMNOPQRSTUVWXYZ%5B%5C%5D%5E_",
			expect: "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_",
		},
		{
			input:  "%60abcdefghijklmnopqrstuvwxyz%7B%7C%7D~",
			expect: "`abcdefghijklmnopqrstuvwxyz{|}~",
		},
		{
			input:  "%7F",
			expect: string([]byte{0x7F}),
		},
		{
			input:  "hello%20world",
			expect: "hello world",
		},
	}

	for i, tt := range tests {
		ret, err := UrlDecode(tt.input)
		if err != nil {
			t.Errorf("[%d] Unexpected error: %s", i, err)
		}
		if diff := cmp.Diff(tt.expect, ret); diff != "" {
			t.Errorf("[%d] Return value unmatch, diff=%s", i, diff)
		}
	}
}
