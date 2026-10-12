package shared

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseQuery(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect *QueryStrings
	}{
		{
			name:   "no query string",
			input:  "/foo",
			expect: &QueryStrings{Prefix: "/foo"},
		},
		{
			name:  "a bare question mark yields one empty parameter",
			input: "/foo?",
			expect: &QueryStrings{Prefix: "/foo", Params: []Param{
				{Name: ""},
			}},
		},
		{
			name:  "distinguishes empty value from no value",
			input: "/?a=&b",
			expect: &QueryStrings{Prefix: "/", Params: []Param{
				{Name: "a", Value: "", HasValue: true},
				{Name: "b"},
			}},
		},
		{
			name:  "keeps duplicates in place",
			input: "/?b=1&a=2&b=3",
			expect: &QueryStrings{Prefix: "/", Params: []Param{
				{Name: "b", Value: "1", HasValue: true},
				{Name: "a", Value: "2", HasValue: true},
				{Name: "b", Value: "3", HasValue: true},
			}},
		},
		{
			name:  "never decodes",
			input: "/?a%20b=x%20y&c=p/q",
			expect: &QueryStrings{Prefix: "/", Params: []Param{
				{Name: "a%20b", Value: "x%20y", HasValue: true},
				{Name: "c", Value: "p/q", HasValue: true},
			}},
		},
		{
			name:  "keeps a valueless duplicate distinct from a valued one",
			input: "/?b&b=1",
			expect: &QueryStrings{Prefix: "/", Params: []Param{
				{Name: "b"},
				{Name: "b", Value: "1", HasValue: true},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.expect, ParseQuery(tt.input)); diff != "" {
				t.Errorf("unmatch: %s", diff)
			}
		})
	}
}

func TestQueryStringsString(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{name: "round trips encoding", input: "/?a=%41&b=x%20y", expect: "/?a=%41&b=x%20y"},
		{name: "round trips duplicate order", input: "/?b=1&a=2&b=3", expect: "/?b=1&a=2&b=3"},
		{name: "round trips a valueless parameter", input: "/?a&b=1", expect: "/?a&b=1"},
		{name: "round trips a bare question mark", input: "/foo?", expect: "/foo?"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseQuery(tt.input).String(); got != tt.expect {
				t.Errorf("expected %q, got %q", tt.expect, got)
			}
		})
	}
}

func TestQueryStringsAdd(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		key, value string
		expect     string
	}{
		{name: "escapes a space as %20", input: "/q?x=1", key: "y", value: "a b", expect: "/q?x=1&y=a%20b"},
		{name: "escapes the name too", input: "/q?x=1", key: "a b", value: "v", expect: "/q?x=1&a%20b=v"},
		{name: "escapes a slash", input: "/q?x=1", key: "y", value: "a/b", expect: "/q?x=1&y=a%2Fb"},
		{name: "double encodes a percent", input: "/q?x=1", key: "y", value: "%41", expect: "/q?x=1&y=%2541"},
		{name: "is a no-op for an empty value", input: "/q?x=1", key: "y", value: "", expect: "/q?x=1"},
		{name: "is a no-op for an empty name", input: "/q?x=1", key: "", value: "v", expect: "/q?x=1"},
		{name: "never deduplicates", input: "/q?x=1", key: "x", value: "2", expect: "/q?x=1&x=2"},
		{name: "appends after a bare question mark", input: "/q?", key: "y", value: "v", expect: "/q?&y=v"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := ParseQuery(tt.input)
			q.Add(tt.key, tt.value)
			if got := q.String(); got != tt.expect {
				t.Errorf("expected %q, got %q", tt.expect, got)
			}
		})
	}
}

func TestQueryStringsSet(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		key, value string
		expect     string
	}{
		{name: "replaces in place and drops later duplicates", input: "/q?a=1&b=2&a=3", key: "a", value: "9", expect: "/q?a=9&b=2"},
		{name: "appends when absent", input: "/q?b=2", key: "a", value: "9", expect: "/q?b=2&a=9"},
		{name: "escapes a space as %20", input: "/q?x=1", key: "x", value: "a b", expect: "/q?x=a%20b"},
		{name: "escapes the name too", input: "/q?x=1", key: "a b", value: "v", expect: "/q?x=1&a%20b=v"},
		{name: "is a no-op for an empty value", input: "/q?x=1", key: "x", value: "", expect: "/q?x=1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := ParseQuery(tt.input)
			q.Set(tt.key, tt.value)
			if got := q.String(); got != tt.expect {
				t.Errorf("expected %q, got %q", tt.expect, got)
			}
		})
	}
}

func TestQueryStringsClean(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{name: "removes empty-named parameters", input: "/q?a=1&&b=2&=v", expect: "/q?a=1&b=2"},
		{name: "keeps valueless parameters", input: "/q?a&b=1", expect: "/q?a&b=1"},
		{name: "keeps duplicates in place", input: "/q?b=1&a=2&b=3", expect: "/q?b=1&a=2&b=3"},
		{name: "preserves encoding", input: "/q?a=%41&b=x%20y&c=p/q", expect: "/q?a=%41&b=x%20y&c=p/q"},
		{name: "a bare question mark yields no query string", input: "/foo?", expect: "/foo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := ParseQuery(tt.input)
			q.Clean()
			if got := q.String(); got != tt.expect {
				t.Errorf("expected %q, got %q", tt.expect, got)
			}
		})
	}
}

func TestQueryStringsFilter(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		keep   func(string) bool
		expect string
	}{
		{
			name:   "keeps duplicates in place",
			input:  "/q?b=1&a=2&b=3",
			keep:   func(n string) bool { return n != "a" },
			expect: "/q?b=1&b=3",
		},
		{
			name:   "preserves encoding",
			input:  "/q?a=%41&b=2",
			keep:   func(n string) bool { return n != "b" },
			expect: "/q?a=%41",
		},
		{
			name:   "matches the raw encoded name",
			input:  "/q?a%20b=1&c=2",
			keep:   func(n string) bool { return n == "a%20b" },
			expect: "/q?a%20b=1",
		},
		{
			name:   "drops empty-named parameters regardless of the predicate",
			input:  "/q?=v&a=1",
			keep:   func(n string) bool { return true },
			expect: "/q?a=1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := ParseQuery(tt.input)
			q.Filter(tt.keep)
			if got := q.String(); got != tt.expect {
				t.Errorf("expected %q, got %q", tt.expect, got)
			}
		})
	}
}

func TestEscape(t *testing.T) {
	tests := []struct {
		name     string
		in, want string
	}{
		{name: "space becomes %20 not plus", in: "a b", want: "a%20b"},
		{name: "slash is escaped", in: "a/b", want: "a%2Fb"},
		{name: "percent is escaped", in: "%41", want: "%2541"},
		{name: "unreserved characters pass through", in: "aZ0-._~", want: "aZ0-._~"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Escape(tt.in); got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}
}
