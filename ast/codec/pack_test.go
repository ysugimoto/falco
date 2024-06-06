package codec

import (
	"bytes"
	"math"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestPack(t *testing.T) {
	tests := []struct {
		astType AstType
		name    string
		input   any
	}{
		{astType: STRING_VALUE, name: "string pack", input: "Lorem Ipsum"},
		{astType: STRING_VALUE, name: "too large string", input: strings.Repeat("example", 1000)},
		{astType: INTEGER_VALUE, name: "integer pack", input: 9999},
		{astType: INTEGER_VALUE, name: "nagative integer pack", input: -99},
		{astType: INTEGER_VALUE, name: "max integer pack", input: math.MaxInt64},
		{astType: INTEGER_VALUE, name: "min integer pack", input: math.MinInt64},
		{astType: FLOAT_VALUE, name: "float pack", input: 10.1245},
		{astType: FLOAT_VALUE, name: "positive infinity pack", input: math.Inf(1)},
		{astType: FLOAT_VALUE, name: "negative infinity pack", input: math.Inf(-1)},
		{astType: BOOL_VALUE, name: "boolean true pack", input: true},
		{astType: BOOL_VALUE, name: "boolean false pack", input: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := []byte("Lorem Ipsum")

			encoded := pack(tt.astType, input)
			at, dec, err := unpack(bytes.NewReader(encoded))
			if err != nil {
				t.Errorf("Unexpected unpacking error: %s", err)
				return
			}
			if at != tt.astType {
				t.Errorf("AstType mismatch between %d vs %d", at, tt.astType)
				return
			}
			if diff := cmp.Diff(input, dec); diff != "" {
				t.Errorf("Decoded input mismatch, diff=%s", diff)
			}
		})
	}
}
