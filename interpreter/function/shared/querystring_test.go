package shared

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestQueryStringsParse(t *testing.T) {
	tests := []struct {
		input  string
		expect *QueryStrings
	}{
		{
			input: "/?foo=",
			expect: &QueryStrings{
				Prefix: "/",
				Items: []*QueryString{
					{
						Key:   "foo",
						Value: []string{""},
					},
				},
			},
		},
		{
			input: "/?foo",
			expect: &QueryStrings{
				Prefix: "/",
				Items: []*QueryString{
					{
						Key:   "foo",
						Value: nil,
					},
				},
			},
		},
		{
			input: "/?a=1&b=2&c=3&d=4&b=5",
			expect: &QueryStrings{
				Prefix: "/",
				Items: []*QueryString{
					{
						Key:   "a",
						Value: []string{"1"},
					},
					{
						Key:   "b",
						Value: []string{"2", "5"},
					},
					{
						Key:   "c",
						Value: []string{"3"},
					},
					{
						Key:   "d",
						Value: []string{"4"},
					},
				},
			},
		},
	}

	for i, tt := range tests {
		q, err := ParseQuery(tt.input)
		if err != nil {
			t.Errorf("[%d] Unexpected parse query error: %s", i, err.Error())
		}
		if diff := cmp.Diff(tt.expect, q); diff != "" {
			t.Errorf("[%d] Result unmatch: diff=: %s", i, diff)
		}
	}
}

func TestQueryStringsAdd(t *testing.T) {
	tests := []struct {
		input  string
		name   string
		value  string
		expect *QueryStrings
	}{
		{
			input: "/?foo",
			name:  "foo",
			value: "bar",
			expect: &QueryStrings{
				Prefix: "/",
				Items: []*QueryString{
					{
						Key:   "foo",
						Value: []string{"bar"},
					},
				},
			},
		},
		{
			input: "/?foo=bar",
			name:  "foo",
			value: "baz",
			expect: &QueryStrings{
				Prefix: "/",
				Items: []*QueryString{
					{
						Key:   "foo",
						Value: []string{"bar", "baz"},
					},
				},
			},
		},
	}

	for i, tt := range tests {
		q, err := ParseQuery(tt.input)
		if err != nil {
			t.Errorf("[%d] Unexpected parse query error: %s", i, err.Error())
		}
		q.Add(tt.name, tt.value)
		if diff := cmp.Diff(tt.expect, q); diff != "" {
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
		q, err := ParseQuery(tt.input)
		if err != nil {
			t.Errorf("[%d] Unexpected parse query error: %s", i, err.Error())
		}
		v := q.Get(tt.name)
		if diff := cmp.Diff(tt.expect, v); diff != "" {
			t.Errorf("[%d] Result unmatch: diff=: %s", i, diff)
		}
	}
}

func TestQueryStringsSet(t *testing.T) {
	tests := []struct {
		input  string
		name   string
		value  string
		expect *QueryStrings
	}{
		{
			input: "/?foo",
			name:  "foo",
			value: "bar",
			expect: &QueryStrings{
				Prefix: "/",
				Items: []*QueryString{
					{
						Key:   "foo",
						Value: []string{"bar"},
					},
				},
			},
		},
		{
			input: "/?foo=bar",
			name:  "foo",
			value: "baz",
			expect: &QueryStrings{
				Prefix: "/",
				Items: []*QueryString{
					{
						Key:   "foo",
						Value: []string{"baz"},
					},
				},
			},
		},
	}

	for i, tt := range tests {
		q, err := ParseQuery(tt.input)
		if err != nil {
			t.Errorf("[%d] Unexpected parse query error: %s", i, err.Error())
		}
		q.Set(tt.name, tt.value)
		if diff := cmp.Diff(tt.expect, q); diff != "" {
			t.Errorf("[%d] Result unmatch: diff=: %s", i, diff)
		}
	}
}

func TestQueryStringsClean(t *testing.T) {
	tests := []struct {
		input  string
		expect *QueryStrings
	}{
		{
			input: "/?foo=bar&&=value-only",
			expect: &QueryStrings{
				Prefix: "/",
				Items: []*QueryString{
					{
						Key:   "foo",
						Value: []string{"bar"},
					},
				},
			},
		},
	}

	for i, tt := range tests {
		q, err := ParseQuery(tt.input)
		if err != nil {
			t.Errorf("[%d] Unexpected parse query error: %s", i, err.Error())
		}
		q.Clean()
		if diff := cmp.Diff(tt.expect, q); diff != "" {
			t.Errorf("[%d] Result unmatch: diff=: %s", i, diff)
		}
	}
}

func TestQueryStringsSort(t *testing.T) {
	tests := []struct {
		input  string
		mode   SortMode
		expect *QueryStrings
	}{
		{
			input: "/?a=b&c=d",
			mode:  SortDesc,
			expect: &QueryStrings{
				Prefix: "/",
				Items: []*QueryString{
					{
						Key:   "c",
						Value: []string{"d"},
					},
					{
						Key:   "a",
						Value: []string{"b"},
					},
				},
			},
		},
		{
			input: "/?c=d&a=b",
			mode:  SortAsc,
			expect: &QueryStrings{
				Prefix: "/",
				Items: []*QueryString{
					{
						Key:   "a",
						Value: []string{"b"},
					},
					{
						Key:   "c",
						Value: []string{"d"},
					},
				},
			},
		},
	}

	for i, tt := range tests {
		q, err := ParseQuery(tt.input)
		if err != nil {
			t.Errorf("[%d] Unexpected parse query error: %s", i, err.Error())
		}
		q.Sort(tt.mode)
		if diff := cmp.Diff(tt.expect, q); diff != "" {
			t.Errorf("[%d] Result unmatch: diff=: %s", i, diff)
		}
	}
}

func TestQueryStringsString(t *testing.T) {
	tests := []struct {
		input  *QueryStrings
		expect string
	}{
		{
			input: &QueryStrings{
				Prefix: "/foo",
				Items: []*QueryString{
					{
						Key:   "a&b",
						Value: []string{"c&d"},
					},
				},
			},
			expect: "/foo?a&b=c&d",
		},
		{
			input: &QueryStrings{
				Prefix: "/foo",
				Items: []*QueryString{
					{
						Key:   "a",
						Value: []string{"b"},
					},
					{
						Key:   "a",
						Value: []string{"c"},
					},
				},
			},
			expect: "/foo?a=b&a=c",
		},
		{
			input: &QueryStrings{
				Prefix: "",
				Items: []*QueryString{
					{
						Key:   "a b",
						Value: []string{"c d"},
					},
				},
			},
			expect: "?a%20b=c%20d",
		},
	}
	for i, test := range tests {
		if diff := cmp.Diff(test.expect, test.input.String()); diff != "" {
			t.Errorf("[%d] Result unmatch: diff=: %s", i, diff)
		}
	}
}
