package ast

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/token"
)

var T = token.Token{}

func comments(c ...string) Comments {
	cs := Comments{}
	for i := range c {
		cs = append(cs, &Comment{
			Value: c[i],
		})
	}
	return cs
}

func assert(t *testing.T, actual, expect string) {
	if diff := cmp.Diff(actual, expect); diff != "" {
		t.Errorf("Stringer error, diff=%s", diff)
	}
}
