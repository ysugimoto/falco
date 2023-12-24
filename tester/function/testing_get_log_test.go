package function

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/process"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_get_log(t *testing.T) {
	ctx := context.New()
	p := process.New()

	tests := []struct {
		args    []value.Value
		logs    []*process.Log
		expect  value.Value
		isError bool
	}{
		{
			args: []value.Value{
				&value.String{Value: "recv"},
			},
			expect:  value.Null,
			isError: true,
		},
		{
			args: []value.Value{
				&value.String{Value: "recv"},
				&value.Integer{Value: 0},
			},
			expect: value.Null,
		},
		{
			args: []value.Value{
				&value.String{Value: "recv"},
				&value.Integer{Value: 0},
			},
			logs: []*process.Log{
				{
					Scope:   "FETCH",
					Message: "test",
				},
			},
			expect: value.Null,
		},
		{
			args: []value.Value{
				&value.String{Value: "recv"},
				&value.Integer{Value: 0},
			},
			logs: []*process.Log{
				{
					Scope:   "RECV",
					Message: "test",
				},
			},
			expect: &value.String{Value: "test"},
		},
		{
			args: []value.Value{
				&value.String{Value: "fetch"},
				&value.Integer{Value: 0},
			},
			logs: []*process.Log{
				{
					Scope:   "RECV",
					Message: "recv log",
				},
				{
					Scope:   "FETCH",
					Message: "fetch log",
				},
				{
					Scope:   "DELIVER",
					Message: "deliver log",
				},
			},
			expect: &value.String{Value: "fetch log"},
		},
	}

	for _, tt := range tests {
		p.Logs = tt.logs
		ret, err := Testing_get_log(ctx, p, tt.args...)
		if tt.isError {
			if err == nil {
				t.Errorf("Expect error but nil")
			}
			continue
		}
		if err != nil {
			t.Errorf("Unexpected error on TestingGetLog, %s", err)
			return
		}
		if diff := cmp.Diff(ret, tt.expect); diff != "" {
			t.Errorf("return value unmatch, diff=%s", diff)
		}
	}
}
