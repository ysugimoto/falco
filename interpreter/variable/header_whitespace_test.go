package variable

import (
	ghttp "net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/v2/interpreter/context"
	"github.com/ysugimoto/falco/v2/interpreter/http"
	"github.com/ysugimoto/falco/v2/interpreter/value"
)

func newHeaderTestContext() *context.Context {
	return &context.Context{
		Request:         http.WrapRequest(httptest.NewRequest(ghttp.MethodGet, "http://localhost", nil)),
		BackendRequest:  http.WrapRequest(httptest.NewRequest(ghttp.MethodGet, "http://localhost", nil)),
		BackendResponse: http.WrapResponse(&ghttp.Response{Header: ghttp.Header{}}),
		Object:          http.WrapResponse(&ghttp.Response{Header: ghttp.Header{}}),
		Response:        http.WrapResponse(&ghttp.Response{Header: ghttp.Header{}}),
	}
}

// Every scope and header object whose set/add statements go through
// setRequestHeaderValue / setResponseHeaderValue and addHeaderValue.
var headerTestScopes = []struct {
	name   string
	vars   func(*context.Context) Variable
	scope  context.Scope
	prefix string
	header func(*context.Context) ghttp.Header
}{
	{
		name:   "req in recv",
		vars:   func(c *context.Context) Variable { return NewRecvScopeVariables(c) },
		scope:  context.RecvScope,
		prefix: "req.http.",
		header: func(c *context.Context) ghttp.Header { return c.Request.Header },
	},
	{
		name:   "bereq in miss",
		vars:   func(c *context.Context) Variable { return NewMissScopeVariables(c) },
		scope:  context.MissScope,
		prefix: "bereq.http.",
		header: func(c *context.Context) ghttp.Header { return c.BackendRequest.Header },
	},
	{
		name:   "bereq in pass",
		vars:   func(c *context.Context) Variable { return NewPassScopeVariables(c) },
		scope:  context.PassScope,
		prefix: "bereq.http.",
		header: func(c *context.Context) ghttp.Header { return c.BackendRequest.Header },
	},
	{
		name:   "bereq in fetch",
		vars:   func(c *context.Context) Variable { return NewFetchScopeVariables(c) },
		scope:  context.FetchScope,
		prefix: "bereq.http.",
		header: func(c *context.Context) ghttp.Header { return c.BackendRequest.Header },
	},
	{
		name:   "beresp in fetch",
		vars:   func(c *context.Context) Variable { return NewFetchScopeVariables(c) },
		scope:  context.FetchScope,
		prefix: "beresp.http.",
		header: func(c *context.Context) ghttp.Header { return c.BackendResponse.Header },
	},
	{
		name:   "obj in hit",
		vars:   func(c *context.Context) Variable { return NewHitScopeVariables(c) },
		scope:  context.HitScope,
		prefix: "obj.http.",
		header: func(c *context.Context) ghttp.Header { return c.Object.Header },
	},
	{
		name:   "obj in error",
		vars:   func(c *context.Context) Variable { return NewErrorScopeVariables(c) },
		scope:  context.ErrorScope,
		prefix: "obj.http.",
		header: func(c *context.Context) ghttp.Header { return c.Object.Header },
	},
	{
		name:   "resp in deliver",
		vars:   func(c *context.Context) Variable { return NewDeliverScopeVariables(c) },
		scope:  context.DeliverScope,
		prefix: "resp.http.",
		header: func(c *context.Context) ghttp.Header { return c.Response.Header },
	},
}

// Fastly strips leading spaces and tabs, and no other whitespace, from the
// value of `set` on a header.
// ref: https://fiddle.fastly.dev/fiddle/8c8d13a1
// ref: https://fiddle.fastly.dev/fiddle/e939e879
// ref: https://fiddle.fastly.dev/fiddle/1f5045d4
func TestSetHeaderValueStripsLeadingWhitespace(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		expect string
	}{
		{name: "leading space", value: " x", expect: "x"},
		{name: "leading spaces", value: "   x", expect: "x"},
		{name: "leading tab", value: "\tx", expect: "x"},
		{name: "mixed spaces and tabs", value: " \t x", expect: "x"},
		{name: "trailing space is kept", value: "y ", expect: "y "},
		{name: "inner space is kept", value: "a b", expect: "a b"},
		{name: "spaces only", value: "   ", expect: ""},
		{name: "carriage return is kept", value: "\rx", expect: "\rx"},
		{name: "vertical tab is kept", value: "\vx", expect: "\vx"},
		{name: "form feed is kept", value: "\fx", expect: "\fx"},
		{name: "spaces before a newline", value: " \nx", expect: ""},
		{name: "trimmed and truncated", value: "  x\n y", expect: "x"},
	}

	for _, sc := range headerTestScopes {
		for _, tt := range tests {
			t.Run(sc.name+" "+tt.name, func(t *testing.T) {
				ctx := newHeaderTestContext()
				vars := sc.vars(ctx)
				if err := vars.Set(sc.scope, sc.prefix+"X", "=", &value.String{Value: tt.value}); err != nil {
					t.Fatalf("Set returned error: %s", err)
				}
				got, err := vars.Get(sc.scope, sc.prefix+"X")
				if err != nil {
					t.Fatalf("Get returned error: %s", err)
				}
				if diff := cmp.Diff(&value.String{Value: tt.expect}, got); diff != "" {
					t.Errorf("Return value unmatch, diff=%s", diff)
				}
			})
		}
	}
}

// The trim applies to the result of `+=`, so a space between the old and the
// appended value is kept.
// ref: https://fiddle.fastly.dev/fiddle/e939e879
func TestAppendAssignHeaderValueKeepsInnerWhitespace(t *testing.T) {
	req := http.WrapRequest(httptest.NewRequest(ghttp.MethodGet, "http://localhost", nil))
	setRequestHeaderValue(req, "X", &value.String{Value: "a"})
	if err := assignRequestHeaderValue(req, "X", "+=", &value.String{Value: " b"}); err != nil {
		t.Fatalf("assignRequestHeaderValue returned error: %s", err)
	}
	if diff := cmp.Diff(&value.String{Value: "a b"}, getRequestHeaderValue(req, "X")); diff != "" {
		t.Errorf("Return value unmatch, diff=%s", diff)
	}
}

// A subfield value with leading whitespace is quoted, so the whitespace is
// kept inside the quotes.
// ref: https://fiddle.fastly.dev/fiddle/e939e879
func TestSetHeaderSubfieldKeepsLeadingWhitespace(t *testing.T) {
	tests := []struct {
		name   string
		before string
		value  string
		expect string
	}{
		{name: "absent header", value: " v", expect: `k=" v"`},
		{name: "existing header", before: "a=1", value: " v", expect: `a=1,k=" v"`},
		{name: "leading tab", value: "\tv", expect: "k=\"\tv\""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := http.WrapRequest(httptest.NewRequest(ghttp.MethodGet, "http://localhost", nil))
			if tt.before != "" {
				setRequestHeaderValue(req, "S", &value.String{Value: tt.before})
			}
			setRequestHeaderValue(req, "S:k", &value.String{Value: tt.value})
			if got := req.Header.Get("S"); got != tt.expect {
				t.Errorf("Header value unmatch, expect=%q, got=%q", tt.expect, got)
			}
		})
	}
}

// Fastly strips leading spaces and tabs from the first `add` on an absent
// header, but keeps them when the header already has a line, even an empty
// one.
// ref: https://fiddle.fastly.dev/fiddle/8c8d13a1
// ref: https://fiddle.fastly.dev/fiddle/e939e879
// ref: https://fiddle.fastly.dev/fiddle/1f5045d4
func TestAddHeaderValueStripsLeadingWhitespaceOnFirstLine(t *testing.T) {
	cases := []struct {
		name   string
		before []string
		unset  bool
		adds   []string
		expect []string
	}{
		{name: "first add on absent header", adds: []string{" x"}, expect: []string{"x"}},
		{name: "first add with tab", adds: []string{"\tx", "y"}, expect: []string{"x", "y"}},
		{name: "first add keeps trailing space", adds: []string{" x", "y "}, expect: []string{"x", "y "}},
		{name: "add onto existing header", before: []string{"a"}, adds: []string{" b"}, expect: []string{"a", " b"}},
		{name: "add tab onto existing header", before: []string{"a"}, adds: []string{"\tb"}, expect: []string{"a", "\tb"}},
		{name: "add onto empty header", before: []string{""}, adds: []string{" b"}, expect: []string{"", " b"}},
		{name: "add after unset", before: []string{"a"}, unset: true, adds: []string{" b"}, expect: []string{"b"}},
	}

	for _, sc := range headerTestScopes {
		for _, tt := range cases {
			t.Run(sc.name+" "+tt.name, func(t *testing.T) {
				ctx := newHeaderTestContext()
				vars := sc.vars(ctx)
				for _, v := range tt.before {
					sc.header(ctx).Add("X", v)
				}
				if tt.unset {
					if err := vars.Unset(sc.scope, sc.prefix+"X"); err != nil {
						t.Fatalf("Unset returned error: %s", err)
					}
				}
				for _, v := range tt.adds {
					if err := vars.Add(sc.scope, sc.prefix+"X", &value.String{Value: v}); err != nil {
						t.Fatalf("Add returned error: %s", err)
					}
				}
				if diff := cmp.Diff(tt.expect, sc.header(ctx).Values("X")); diff != "" {
					t.Errorf("Header lines unmatch, diff=%s", diff)
				}
			})
		}
	}
}

// Header names are case-insensitive, so an add onto the same header under
// another spelling is not a first line and keeps its leading whitespace.
func TestAddHeaderValueOntoDifferentCaseKeepsWhitespace(t *testing.T) {
	for _, sc := range headerTestScopes {
		t.Run(sc.name, func(t *testing.T) {
			ctx := newHeaderTestContext()
			vars := sc.vars(ctx)
			if err := vars.Set(sc.scope, sc.prefix+"x-foo", "=", &value.String{Value: "a"}); err != nil {
				t.Fatalf("Set returned error: %s", err)
			}
			if err := vars.Add(sc.scope, sc.prefix+"X-FOO", &value.String{Value: " b"}); err != nil {
				t.Fatalf("Add returned error: %s", err)
			}
			if diff := cmp.Diff([]string{"a", " b"}, sc.header(ctx).Values("X-Foo")); diff != "" {
				t.Errorf("Header lines unmatch, diff=%s", diff)
			}
		})
	}
}

// An add of an empty or whitespace-only value onto an absent header leaves
// the header set, with an empty value.
// ref: https://fiddle.fastly.dev/fiddle/5d8a1500
func TestAddEmptyHeaderValueLeavesHeaderSet(t *testing.T) {
	for _, sc := range headerTestScopes {
		for _, v := range []string{"", "   ", "\t"} {
			t.Run(sc.name+" "+strconv.Quote(v), func(t *testing.T) {
				ctx := newHeaderTestContext()
				vars := sc.vars(ctx)
				if err := vars.Add(sc.scope, sc.prefix+"X", &value.String{Value: v}); err != nil {
					t.Fatalf("Add returned error: %s", err)
				}
				got, err := vars.Get(sc.scope, sc.prefix+"X")
				if err != nil {
					t.Fatalf("Get returned error: %s", err)
				}
				if diff := cmp.Diff(&value.String{Value: ""}, got); diff != "" {
					t.Errorf("Return value unmatch, diff=%s", diff)
				}
			})
		}
	}
}
