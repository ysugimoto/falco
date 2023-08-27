package function

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_Assert_not_match(t *testing.T) {

	tests := []struct {
		args   []value.Value
		err    error
		expect *value.Boolean
	}{
		{
			args: []value.Value{
				&value.String{Value: "foobarbaz"},
				&value.String{Value: ".*bat.*"},
			},
			expect: &value.Boolean{Value: true},
		},
		{
			args: []value.Value{
				&value.String{Value: "foobarbaz"},
				&value.String{Value: ".*bar.*"},
			},
			expect: &value.Boolean{Value: false},
			err:    &errors.AssertionError{},
		},
		{
			args: []value.Value{
				&value.String{Value: "foobarbaz"},
				&value.Integer{Value: 0},
			},
			expect: nil,
			err:    &errors.TestingError{},
		},
		{
			args: []value.Value{
				&value.String{Value: "foobarbaz"},
				&value.String{Value: ".*bar.*"},
				&value.String{Value: "custom_message"},
			},
			expect: nil,
			err: &errors.AssertionError{
				Message: "custom_message",
			},
		},
		{
			args: []value.Value{
				&value.String{Value: "foobarbaz"},
				&value.String{Value: "^++a"},
			},
			expect: nil,
			err:    &errors.TestingError{},
		},
	}

	for i := range tests {
		_, err := Assert_not_match(
			&context.Context{},
			tests[i].args...,
		)
		if diff := cmp.Diff(
			tests[i].err,
			err,
			cmpopts.IgnoreFields(errors.AssertionError{}, "Message", "Actual"),
			cmpopts.IgnoreFields(errors.TestingError{}, "Message"),
		); diff != "" {
			t.Errorf("Assert_not_match()[%d] error: diff=%s", i, diff)
		}
	}
}
