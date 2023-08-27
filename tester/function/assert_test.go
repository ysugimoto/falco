package function

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_Assert(t *testing.T) {

	tests := []struct {
		args   []value.Value
		err    error
		expect *value.Boolean
	}{
		{
			args: []value.Value{
				&value.Boolean{},
			},
			err:    &errors.AssertionError{},
			expect: &value.Boolean{},
		},
		{
			args: []value.Value{
				&value.Boolean{Value: true},
			},
			expect: &value.Boolean{Value: false},
		},
		{
			args: []value.Value{
				&value.Boolean{Value: true},
				&value.Boolean{Value: true},
			},
			err:    &errors.TestingError{},
			expect: &value.Boolean{Value: false},
		},
	}

	for i := range tests {
		_, err := Assert(
			&context.Context{},
			tests[i].args...,
		)
		if diff := cmp.Diff(
			tests[i].err,
			err,
			cmpopts.IgnoreFields(errors.AssertionError{}, "Message", "Actual"),
			cmpopts.IgnoreFields(errors.TestingError{}, "Message"),
		); diff != "" {
			t.Errorf("Assert()[%d] error: diff=%s", i, diff)
		}
	}
}
