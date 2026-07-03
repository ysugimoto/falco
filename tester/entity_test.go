package tester

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/v2/interpreter/function/errors"
	"github.com/ysugimoto/falco/v2/token"
)

func TestTestCaseMarshalJSON(t *testing.T) {
	tok := token.Token{
		File:     "main.vcl",
		Line:     42,
		Position: 7,
	}

	// num returns the json.Number a numeric field decodes to, so expectations
	// can be written without worrying about float64 round-tripping.
	num := func(n int) json.Number { return json.Number(strconv.Itoa(n)) }

	tests := []struct {
		name  string
		input *TestCase
		// expect is the exact decoded JSON object. Keys that must be omitted
		// (file/line/position/error/group) are simply absent here, which the
		// map comparison enforces directly.
		expect map[string]any
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
			expect: map[string]any{
				"name":         "passes",
				"group":        "group-a",
				"scope":        "recv",
				"elapsed_time": num(12),
				"skip":         false,
				"logs":         []any{"log line"},
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
			expect: map[string]any{
				"name":         "asserts",
				"scope":        "fetch",
				"elapsed_time": num(3),
				"skip":         false,
				"logs":         []any{},
				"error":        "expected true",
				"file":         tok.File,
				"line":         num(tok.Line),
				"position":     num(tok.Position),
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
			expect: map[string]any{
				"name":         "testing",
				"scope":        "deliver",
				"elapsed_time": num(5),
				"skip":         false,
				"logs":         []any{},
				"error":        "something went wrong",
				"file":         tok.File,
				"line":         num(tok.Line),
				"position":     num(tok.Position),
			},
		},
		{
			name: "generic error sets error but omits file, line and position",
			input: &TestCase{
				Name:  "generic",
				Scope: "recv",
				Time:  1,
				Logs:  []string{},
				Error: fmt.Errorf("boom"),
			},
			expect: map[string]any{
				"name":         "generic",
				"scope":        "recv",
				"elapsed_time": num(1),
				"skip":         false,
				"logs":         []any{},
				"error":        "boom",
			},
		},
		{
			name: "zero-valued token location is omitted",
			input: &TestCase{
				Name:  "zero-token",
				Scope: "recv",
				Time:  1,
				Logs:  []string{},
				Error: &errors.AssertionError{
					Token:   token.Token{}, // File "", Line 0, Position 0
					Message: "no location",
				},
			},
			expect: map[string]any{
				"name":         "zero-token",
				"scope":        "recv",
				"elapsed_time": num(1),
				"skip":         false,
				"logs":         []any{},
				"error":        "no location",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatalf("unexpected marshal error: %s", err)
			}

			// Decode into a generic object so that key presence/absence and key
			// names are asserted directly, instead of round-tripping through a
			// struct (which hides omitempty behaviour and tag typos).
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.UseNumber()
			var actual map[string]any
			if err := dec.Decode(&actual); err != nil {
				t.Fatalf("unexpected unmarshal error: %s", err)
			}

			if diff := cmp.Diff(tt.expect, actual); diff != "" {
				t.Errorf("TestCase JSON mismatch (-want +got):\n%s\nraw=%s", diff, b)
			}
		})
	}
}
