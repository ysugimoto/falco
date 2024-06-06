package codec

import (
	"bytes"
	"math"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestPackString(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "string pack", input: "Lorem Ipsum"},
		{name: "large string", input: strings.Repeat("example", 1000)},
		{name: "extreme large string", input: strings.Repeat("a", 65535)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := packString(tt.input)
			str, err := unpackString(bytes.NewReader(encoded))
			if err != nil {
				t.Errorf("Unexpected unpacking error: %s", err)
				return
			}
			if diff := cmp.Diff(tt.input, str.Value); diff != "" {
				t.Errorf("Decoded result mismatch, diff=%s", diff)
			}
		})
	}
}

func TestPackInteger(t *testing.T) {
	tests := []struct {
		name  string
		input int64
	}{
		{name: "integer pack", input: 9999},
		{name: "nagative integer pack", input: -99},
		{name: "max integer pack", input: math.MaxInt64},
		{name: "min integer pack", input: math.MinInt64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := packInteger(tt.input)
			i, err := unpackInteger(bytes.NewReader(encoded))
			if err != nil {
				t.Errorf("Unexpected unpacking error: %s", err)
				return
			}
			if diff := cmp.Diff(tt.input, i.Value); diff != "" {
				t.Errorf("Decoded input mismatch, diff=%s", diff)
			}
		})
	}
}

func TestPackFloat(t *testing.T) {
	tests := []struct {
		name  string
		input float64
	}{
		{name: "float pack", input: 10.1245},
		{name: "positive infinity pack", input: math.Inf(1)},
		{name: "negative infinity pack", input: math.Inf(-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := packFloat(tt.input)
			f, err := unpackFloat(bytes.NewReader(encoded))
			if err != nil {
				t.Errorf("Unexpected unpacking error: %s", err)
				return
			}
			if diff := cmp.Diff(tt.input, f.Value); diff != "" {
				t.Errorf("Decoded input mismatch, diff=%s", diff)
			}
		})
	}
}

func TestPackBoolean(t *testing.T) {
	tests := []struct {
		name  string
		input bool
	}{
		{name: "boolean true pack", input: true},
		{name: "boolean false pack", input: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := packBoolean(tt.input)
			b, err := unpackBoolean(bytes.NewReader(encoded))
			if err != nil {
				t.Errorf("Unexpected unpacking error: %s", err)
				return
			}
			if diff := cmp.Diff(tt.input, b.Value); diff != "" {
				t.Errorf("Decoded input mismatch, diff=%s", diff)
			}
		})
	}
}
