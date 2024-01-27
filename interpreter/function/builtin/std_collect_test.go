// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	flchttp "github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of std.collect
// Arguments may be:
// - ID
// - ID, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/miscellaneous/std-collect/
func Test_Std_collect(t *testing.T) {

	tests := []struct {
		header    string
		values    []string
		expect    [][]flchttp.HeaderItem
		separator string
		isError   bool
	}{
		{
			header: "Foo",
			values: []string{"bar", "baz"},
			expect: [][]flchttp.HeaderItem{
				{
					{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
						Value: nil,
					},
					{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "baz"},
							},
						},
						Value: nil,
					},
				},
			},
		},
		{
			header: "Cookie",
			values: []string{"foo=bar", "bar=baz"},
			expect: [][]flchttp.HeaderItem{
				{
					{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "foo=bar"},
							},
						},
						Value: nil,
					},
					{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar=baz"},
							},
						},
						Value: nil,
					},
				},
			},
			separator: ";",
		},
		{
			header:  "Set-Cookie",
			values:  []string{"foo=bar", "foo=baz"},
			isError: true,
		},
	}

	for i, tt := range tests {
		req, err := flchttp.NewRequest(http.MethodGet, "https://example.com", nil)
		if err != nil {
			t.Errorf("[%d] Unexpected request creation error: %s", i, err)
		}
		for _, v := range tt.values {
			req.Header.Add(tt.header, &value.String{Value: v})
		}
		args := []value.Value{
			&value.Ident{Value: "req.http." + tt.header},
		}
		if tt.separator != "" {
			args = append(args, &value.String{Value: tt.separator})
		}
		_, err = Std_collect(
			&context.Context{Request: req},
			args...,
		)

		if tt.isError {
			if err == nil {
				t.Errorf("[%d] Expects error but nil", i)
				return
			}
			return
		} else {
			if err != nil {
				t.Errorf("[%d] Unexpected error returned non-nil: %s", i, err)
				return
			}
		}

		if diff := cmp.Diff(tt.expect, req.Header[tt.header]); diff != "" {
			t.Errorf("[%d] After std.collect result mismatch, diff=%s", i, diff)
		}
	}
}
