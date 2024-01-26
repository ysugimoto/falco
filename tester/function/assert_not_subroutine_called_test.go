package function

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_Assert_not_subroutine_called(t *testing.T) {

	tests := []struct {
		args   []value.Value
		err    error
		expect *value.Boolean
	}{
		{
			args: []value.Value{
				&value.String{Value: "counter_recv_not_called"},
			},
			expect: &value.Boolean{Value: true},
		},
		{
			args: []value.Value{
				&value.String{Value: "counter_recv"},
			},
			expect: &value.Boolean{Value: false},
			err:    &errors.AssertionError{},
		},
		{
			args: []value.Value{
				&value.String{Value: "counter_recv"},
				&value.String{Value: "custom_message"},
			},
			expect: &value.Boolean{Value: false},
			err:    &errors.AssertionError{},
		},
	}

	for i := range tests {
		_, err := Assert_not_subroutine_called(
			&context.Context{
				SubroutineCalls: map[string]int{
					"counter_recv": 1,
				},
			},
			tests[i].args...,
		)
		if diff := cmp.Diff(
			tests[i].err,
			err,
			cmpopts.IgnoreFields(errors.AssertionError{}, "Message", "Actual"),
			cmpopts.IgnoreFields(errors.TestingError{}, "Message"),
		); diff != "" {
			t.Errorf("Assert_not_subroutine_called()[%d] error: diff=%s", i, diff)
		}
	}
}
