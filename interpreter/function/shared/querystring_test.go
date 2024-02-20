package shared

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestKeyEncoding(t *testing.T) {
	tests := []struct {
		input  []string
		expect string
	}{
		{
			input:  []string{"?a b=c", "a b", "d"},
			expect: "?a b=c&a%20b=d",
		},
		{
			input:  []string{"?a b=c", "a%20b", "d"},
			expect: "?a b=c&a%2520b=d",
		},
		{
			input:  []string{"?a%20b=c", "a b", "d"},
			expect: "?a%20b=d",
		},
		{
			input:  []string{"?a%20b=c", "a%20b", "d"},
			expect: "?a%20b=c&a%2520b=d",
		},
		{
			input:  []string{"?", "a", "b"},
			expect: "?&a=b", // Fastly blindly inserts '&' before added param
		},
		{
			input:  []string{"path", "a", "b"},
			expect: "path?a=b",
		},
		{
			input:  []string{"/?foo", "foo", "bar"},
			expect: "/?foo=bar",
		},
	}
	for i, tt := range tests {
		args := tt.input
		result := QueryStringSet(args[0], args[1], args[2])
		if diff := cmp.Diff(tt.expect, result); diff != "" {
			t.Errorf("[%d] Result unmatch: diff=: %s", i, diff)
		}
	}
}

func TestQueryStringsAdd(t *testing.T) {
	tests := []struct {
		input  []string
		expect string
	}{
		{
			input:  []string{"", "foo", "bar"},
			expect: "?foo=bar",
		},
		{
			input:  []string{"?", "foo", "bar"},
			expect: "?&foo=bar",
		},
		{
			input:  []string{"/?foo", "foo", "bar"},
			expect: "/?foo&foo=bar",
		},
		{
			input:  []string{"/?foo=bar", "foo", "baz"},
			expect: "/?foo=bar&foo=baz",
		},
	}

	for i, tt := range tests {
		args := tt.input
		result := QueryStringAdd(args[0], args[1], args[2])
		if diff := cmp.Diff(tt.expect, result); diff != "" {
			t.Errorf("[%d] Result unmatch: diff=: %s", i, diff)
		}
	}
}

func TestQueryStringsGet(t *testing.T) {
	tests := []struct {
		input  string
		name   string
		expect *string
	}{
		{
			input:  "/?foo",
			name:   "foo",
			expect: nil,
		},
		{
			input: "/?foo=bar",
			name:  "foo",
			expect: func() *string {
				s := "bar"
				return &s
			}(),
		},
	}

	for i, tt := range tests {
		v := QueryStringGet(tt.input, tt.name)
		if diff := cmp.Diff(tt.expect, v); diff != "" {
			t.Errorf("[%d] Result unmatch: diff=: %s", i, diff)
		}
	}
}

func TestQueryStringsClean(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{
			input:  "/path?",
			expect: "/path",
		},
		{
			input:  "/?foo=bar&&=value-only",
			expect: "/?foo=bar",
		},
		{
			input:  "/path?&&&&====&&&&foo=&bar=",
			expect: "/path?foo=&bar=",
		},
	}

	for i, tt := range tests {
		result := QueryStringClean(tt.input)
		if diff := cmp.Diff(tt.expect, result); diff != "" {
			t.Errorf("[%d] Result unmatch: diff=: %s", i, diff)
		}
	}
}

func TestQueryStringsSort(t *testing.T) {
	tests := []struct {
		input  string
		mode   SortMode
		expect string
	}{
		{input: "", mode: SortDesc, expect: ""},
		{input: "?", mode: SortDesc, expect: "?"},
		{input: "/path", mode: SortDesc, expect: "/path"},
		{input: "/path?", mode: SortDesc, expect: "/path?"},
		{input: "/?a=b&c=d", mode: SortDesc, expect: "/?c=d&a=b"},
		{input: "/?c=d&a=b", mode: SortAsc, expect: "/?a=b&c=d"},
		{input: "?foo=one&f%6fo=two&f%6Fo=three", mode: SortAsc, expect: "?f%6Fo=three&f%6fo=two&foo=one"},
		{input: "?foo=b&foo=a&foo=c", mode: SortAsc, expect: "?foo=a&foo=b&foo=c"},
		{input: "?foo=bar&foo<=bar&foo>=bar", mode: SortAsc, expect: "?foo<=bar&foo=bar&foo>=bar"},
	}

	for i, tt := range tests {
		result := QueryStringSort(tt.input, tt.mode)
		if diff := cmp.Diff(tt.expect, result); diff != "" {
			t.Errorf("[%d] Result unmatch: diff=: %s", i, diff)
		}
	}
}
