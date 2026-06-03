package tester

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/token"
)

func TestTestCaseMarshalJSON(t *testing.T) {
	tok := token.Token{
		File:     "main.vcl",
		Line:     42,
		Position: 7,
	}

	type wire struct {
		Name     string   `json:"name"`
		Error    string   `json:"error,omitempty"`
		Group    string   `json:"group,omitempty"`
		Scope    string   `json:"scope"`
		Time     int64    `json:"elapsed_time"`
		Skip     bool     `json:"skip"`
		Logs     []string `json:"logs"`
		File     string   `json:"file,omitempty"`
		Line     int      `json:"line,omitempty"`
		Position int      `json:"position,omitempty"`
	}

	tests := []struct {
		name   string
		input  *TestCase
		expect wire
	}{
		{
			name: "no error omits file, line and position",
			input: &TestCase{
				Name:  "passes",
				Group: "group-a",
				Scope: "recv",
				Time:  12,
				Skip:  false,
				Logs:  []string{"log line"},
			},
			expect: wire{
				Name:  "passes",
				Group: "group-a",
				Scope: "recv",
				Time:  12,
				Logs:  []string{"log line"},
			},
		},
		{
			name: "assertion error serializes file, line and position",
			input: &TestCase{
				Name:  "asserts",
				Scope: "fetch",
				Time:  3,
				Logs:  []string{},
				Error: &errors.AssertionError{
					Token:   tok,
					Message: "expected true",
				},
			},
			expect: wire{
				Name:     "asserts",
				Scope:    "fetch",
				Time:     3,
				Logs:     []string{},
				Error:    "expected true",
				File:     tok.File,
				Line:     tok.Line,
				Position: tok.Position,
			},
		},
		{
			name: "testing error serializes file, line and position",
			input: &TestCase{
				Name:  "testing",
				Scope: "deliver",
				Time:  5,
				Logs:  []string{},
				Error: &errors.TestingError{
					Token:   tok,
					Message: "something went wrong",
				},
			},
			expect: wire{
				Name:     "testing",
				Scope:    "deliver",
				Time:     5,
				Logs:     []string{},
				Error:    "something went wrong",
				File:     tok.File,
				Line:     tok.Line,
				Position: tok.Position,
			},
		},
		{
			name: "generic error does not set file, line and position",
			input: &TestCase{
				Name:  "generic",
				Scope: "recv",
				Time:  1,
				Logs:  []string{},
				Error: fmt.Errorf("boom"),
			},
			expect: wire{
				Name:  "generic",
				Scope: "recv",
				Time:  1,
				Logs:  []string{},
				Error: "boom",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatalf("unexpected marshal error: %s", err)
			}
			var actual wire
			if err := json.Unmarshal(b, &actual); err != nil {
				t.Fatalf("unexpected unmarshal error: %s", err)
			}
			if diff := cmp.Diff(tt.expect, actual); diff != "" {
				t.Errorf("TestCase JSON mismatch, diff=%s", diff)
			}
		})
	}
}
