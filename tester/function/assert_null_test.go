package function

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_Assert_null(t *testing.T) {

	tests := []struct {
		args   []value.Value
		err    error
		expect *value.Boolean
	}{
		{
			args: []value.Value{
				value.Null,
			},
			expect: &value.Boolean{Value: true},
		},
		{
			args: []value.Value{
				&value.String{IsNotSet: true},
			},
			expect: &value.Boolean{Value: true},
		},
		{
			args: []value.Value{
				&value.IP{IsNotSet: true},
			},
			expect: &value.Boolean{Value: true},
		},
		{
			args: []value.Value{
				&value.Integer{},
			},
			expect: &value.Boolean{Value: false},
			err:    &errors.AssertionError{},
		},
	}

	for i := range tests {
		_, err := Assert_null(
			&context.Context{},
			tests[i].args...,
		)
		if diff := cmp.Diff(
			tests[i].err,
			err,
			cmpopts.IgnoreFields(errors.AssertionError{}, "Message", "Actual"),
			cmpopts.IgnoreFields(errors.TestingError{}, "Message"),
		); diff != "" {
			t.Errorf("Assert_null()[%d] error: diff=%s", i, diff)
		}
	}
}
