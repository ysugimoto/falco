package http

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestReadCookies(t *testing.T) {
	cookieHeader := [][]HeaderItem{
		{
			HeaderItem{
				Key: &value.LenientString{
					Values: []value.Value{
						&value.String{Value: "foo"},
					},
				},
				Value: &value.LenientString{
					Values: []value.Value{
						&value.String{Value: "bar"},
					},
				},
			},
			HeaderItem{
				Key: &value.LenientString{
					Values: []value.Value{
						&value.String{Value: "dog"},
					},
				},
				Value: &value.LenientString{
					Values: []value.Value{
						&value.String{Value: "bark"},
					},
				},
			},
		},
	}
	cookies := readCookies(cookieHeader)
	expect := []*Cookie{
		{Name: "foo", Value: "bar"},
		{Name: "dog", Value: "bark"},
	}
	if diff := cmp.Diff(expect, cookies); diff != "" {
		t.Errorf("Cookie mismatch, diff=%s", diff)
	}
}
