package value

import (
	"testing"
	"time"
)

func TestParseRTimeLiteral(t *testing.T) {
	tests := []struct {
		input   string
		expect  time.Duration
		isError bool
	}{
		{input: "100ms", expect: 100 * time.Millisecond},
		{input: "5s", expect: 5 * time.Second},
		{input: "5m", expect: 5 * time.Minute},
		{input: "6h", expect: 6 * time.Hour},
		{input: "3d", expect: 3 * 24 * time.Hour},
		{input: "8w", expect: 8 * 7 * 24 * time.Hour},
		{input: "1y", expect: 365 * 24 * time.Hour},
		{input: "5.3d", expect: time.Duration(5.3 * float64(24*time.Hour))},
		{input: "1.5w", expect: time.Duration(1.5 * float64(7*24*time.Hour))},
		{input: "-1w", expect: -7 * 24 * time.Hour},
		{input: "100000000000w", isError: true}, // overflows time.Duration
		{input: "notanumber", isError: true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseRTimeLiteral(tt.input)
			if tt.isError {
				if err == nil {
					t.Errorf("expected error for %q, got %s", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error for %q: %s", tt.input, err)
				return
			}
			if got != tt.expect {
				t.Errorf("for %q expected %s, got %s", tt.input, tt.expect, got)
			}
		})
	}
}
