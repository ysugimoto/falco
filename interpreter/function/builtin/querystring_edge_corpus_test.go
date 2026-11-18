package builtin

import (
	"testing"

	"github.com/ysugimoto/falco/v2/interpreter/context"
	"github.com/ysugimoto/falco/v2/interpreter/value"
)

// Test_QuerystringEdgeCorpus covers shared query string behavior across the builtin family.
func Test_QuerystringEdgeCorpus(t *testing.T) {
	s := func(v string) *value.String { return &value.String{Value: v} }
	b := func(v bool) *value.Boolean { return &value.Boolean{Value: v} }
	ctx := &context.Context{}

	tests := []struct {
		name   string
		call   func() (value.Value, error)
		expect string
	}{
		{
			name:   "get does not decode",
			call:   func() (value.Value, error) { return Querystring_get(ctx, s("/q?a=%41&b=2"), s("a")) },
			expect: "%41",
		},
		{
			name:   "get returns the first duplicate",
			call:   func() (value.Value, error) { return Querystring_get(ctx, s("/q?a=1&a=2"), s("a")) },
			expect: "1",
		},
		{
			name:   "get skips a valueless match and keeps searching",
			call:   func() (value.Value, error) { return Querystring_get(ctx, s("/q?a&a=1"), s("a")) },
			expect: "1",
		},
		{
			name:   "sort orders whole tokens",
			call:   func() (value.Value, error) { return Querystring_sort(ctx, s("/q?b=2&b=1&a=0")) },
			expect: "/q?a=0&b=1&b=2",
		},
		{
			name:   "sort compares values bytewise",
			call:   func() (value.Value, error) { return Querystring_sort(ctx, s("/q?b=9&b=10&a=0")) },
			expect: "/q?a=0&b=10&b=9",
		},
		{
			name:   "sort leaves 32 parameters alone",
			call:   func() (value.Value, error) { return Querystring_sort(ctx, s(descendingParams(32))) },
			expect: descendingParams(32),
		},
		{
			name:   "sort keeps a bare question mark",
			call:   func() (value.Value, error) { return Querystring_sort(ctx, s("/foo?")) },
			expect: "/foo?",
		},
		{
			name:   "only_unique_keys keeps the first occurrence",
			call:   func() (value.Value, error) { return Querystring_sort(ctx, s("/test?a=7&a=2&a=1&b=5&b=3"), b(true)) },
			expect: "/test?a=7&b=5",
		},
		{
			name:   "clean keeps duplicates in place",
			call:   func() (value.Value, error) { return Querystring_clean(ctx, s("/q?b=1&a=2&b=3")) },
			expect: "/q?b=1&a=2&b=3",
		},
		{
			name:   "clean preserves encoding",
			call:   func() (value.Value, error) { return Querystring_clean(ctx, s("/q?a=%41&b=x%20y&c=p/q")) },
			expect: "/q?a=%41&b=x%20y&c=p/q",
		},
		{
			name:   "clean keeps a valueless parameter distinct from a same-named valued one",
			call:   func() (value.Value, error) { return Querystring_clean(ctx, s("/q?b&b=1")) },
			expect: "/q?b&b=1",
		},
		{
			name:   "filter preserves encoding",
			call:   func() (value.Value, error) { return Querystring_filter(ctx, s("/q?a=%41&b=2"), s("b")) },
			expect: "/q?a=%41",
		},
		{
			name:   "filter_except drops an empty-named parameter and anything not kept",
			call:   func() (value.Value, error) { return Querystring_filter_except(ctx, s("/q?=v&a=1&b=2"), s("a")) },
			expect: "/q?a=1",
		},
		{
			name:   "filter_except leaves the url unchanged for an empty keep-list",
			call:   func() (value.Value, error) { return Querystring_filter_except(ctx, s("/q?a=1&b=2"), s("")) },
			expect: "/q?a=1&b=2",
		},

		// Empty names are discarded before evaluating each filter predicate.
		{
			name:   "filter drops an empty-named parameter absent from the remove-list",
			call:   func() (value.Value, error) { return Querystring_filter(ctx, s("/q?=v&a=1&b=2"), s("b")) },
			expect: "/q?a=1",
		},
		{
			name: "filter_except drops an empty-named parameter that is on the keep-list",
			call: func() (value.Value, error) {
				return Querystring_filter_except(ctx, s("/q?=v&a=1&b=2"), s("a\xff"))
			},
			expect: "/q?a=1",
		},
		{
			name:   "globfilter drops an empty-named parameter the glob does not match",
			call:   func() (value.Value, error) { return Querystring_globfilter(ctx, s("/q?=v&a=1&b=2"), s("b*")) },
			expect: "/q?a=1",
		},
		{
			name: "globfilter_except drops an empty-named parameter matched by a catch-all glob",
			call: func() (value.Value, error) {
				return Querystring_globfilter_except(ctx, s("/q?=v&a=1&b=2"), s("*"))
			},
			expect: "/q?a=1&b=2",
		},
		{
			name:   "regfilter drops an empty-named parameter the regexp does not match",
			call:   func() (value.Value, error) { return Querystring_regfilter(ctx, s("/q?=v&a=1&b=2"), s("^b$")) },
			expect: "/q?a=1",
		},
		{
			name: "regfilter_except drops an empty-named parameter matched by the regexp",
			call: func() (value.Value, error) {
				return Querystring_regfilter_except(ctx, s("/q?=v&a=1&b=2"), s("^(|a)$"))
			},
			expect: "/q?a=1",
		},
		{
			name:   "add writes a space as %20",
			call:   func() (value.Value, error) { return Querystring_add(ctx, s("/q?x=1"), s("y"), s("a b")) },
			expect: "/q?x=1&y=a%20b",
		},
		{
			name:   "add escapes the name too",
			call:   func() (value.Value, error) { return Querystring_add(ctx, s("/q?x=1"), s("a b"), s("v")) },
			expect: "/q?x=1&a%20b=v",
		},
		{
			name:   "add is a no-op for an empty value",
			call:   func() (value.Value, error) { return Querystring_add(ctx, s("/q?x=1"), s("y"), s("")) },
			expect: "/q?x=1",
		},
		{
			name:   "set replaces in place and drops later duplicates",
			call:   func() (value.Value, error) { return Querystring_set(ctx, s("/q?a=1&b=2&a=3"), s("a"), s("9")) },
			expect: "/q?a=9&b=2",
		},
		{
			name:   "set is a no-op for an empty value",
			call:   func() (value.Value, error) { return Querystring_set(ctx, s("/q?x=1"), s("x"), s("")) },
			expect: "/q?x=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, err := tt.call()
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if got := value.Unwrap[*value.String](ret).Value; got != tt.expect {
				t.Errorf("expected %q, got %q", tt.expect, got)
			}
		})
	}
}
