package parser

import (
	"testing"
)

func TestParseString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		expect  string
		isError bool
	}{
		// %xx utf-8 format
		{
			name:   "%xx Single byte ($)",
			input:  "%24",
			expect: "$",
		},
		{
			name:   "%xx Double byte (£)",
			input:  "%c2%a3",
			expect: "£",
		},
		{
			name:   "%xx Double byte (И)",
			input:  "%d0%98",
			expect: "И",
		},
		{
			name:   "%xx Triple byte (ह)",
			input:  "%E0%A4%B9",
			expect: "ह",
		},
		{
			name:   "%xx Triple byte (€)",
			input:  "%E2%82%AC",
			expect: "€",
		},
		{
			name:   "%xx Triple byte (한)",
			input:  "%ED%95%9C",
			expect: "한",
		},
		{
			name:   "%xx Quad byte (𐍈)",
			input:  "%F0%90%8D%88",
			expect: "𐍈",
		},
		{
			name:   "%xx Single null byte",
			input:  "%00",
			expect: "",
		},
		{
			name:   "%xx Null byte terminates string",
			input:  "foo%00bar",
			expect: "foo",
		},
		{
			name:    "%xx Code point out of range",
			input:   "%F0%FF%FF%FF",
			isError: true,
		},
		{
			name:    "%xx Surrogate code point",
			input:   "%ed%a0%80",
			isError: true,
		},
		{
			name:    "%xx Surrogate code point",
			input:   "%ed%bf%bf",
			isError: true,
		},
		{
			name:    "%xx Multi-byte zero",
			input:   "%F0%00%00%00",
			isError: true,
		},
		{
			name:    "%xx Missing second byte",
			input:   "%d0",
			isError: true,
		},
		{
			name:    "%xx Too few hex digits",
			input:   "%F",
			isError: true,
		},
		{
			name:    "%xx Too few hex digits in second byte",
			input:   "%d0%d",
			isError: true,
		},
		{
			name:    "%xx No hex digits",
			input:   "%",
			isError: true,
		},
		{
			name:    "%xx ",
			input:   "%80",
			isError: true,
		},
		{
			name:    "%xx ",
			input:   "%f8",
			isError: true,
		},

		// %u fixed width code point format
		{
			name:   "%u Two digit code point ($)",
			input:  "%u0024",
			expect: "$",
		},
		{
			name:   "%u Two digit code point (£)",
			input:  "%u00A3",
			expect: "£",
		},
		{
			name:   "%u Three digit code point (И)",
			input:  "%u0418",
			expect: "И",
		},
		{
			name:   "%u Three digit code point (ह)",
			input:  "%u0939",
			expect: "ह",
		},
		{
			name:   "%u Four digit code point (€)",
			input:  "%u20AC",
			expect: "€",
		},
		{
			name:   "%u Four digit code point (한)",
			input:  "%uD55C",
			expect: "한",
		},
		{
			name:   "%u Hex digit after escape",
			input:  "%uD55C1",
			expect: "한1",
		},
		{
			name:   "%u Null byte",
			input:  "%0000",
			expect: "",
		},
		{
			name:   "%u Null byte terminates string",
			input:  "foo%u0000bar",
			expect: "foo",
		},
		{
			name:    "%u Not enough hex digits",
			input:   "%uD55",
			isError: true,
		},
		{
			name:    "%u Missing code point",
			input:   "%u",
			isError: true,
		},
		{
			name:    "%u Surrogate code point",
			input:   "%uD800",
			isError: true,
		},
		{
			name:    "%u Surrogate code point",
			input:   "%uDFFF",
			isError: true,
		},

		// %u{} variable length code point format
		{
			name:   "%u{} Two digit code point ($)",
			input:  "%u{24}",
			expect: "$",
		},
		{
			name:   "%u{} Two digit code point (£)",
			input:  "%u{A3}",
			expect: "£",
		},
		{
			name:   "%u{} Three digit code point (И)",
			input:  "%u{418}",
			expect: "И",
		},
		{
			name:   "%u{} Three digit code point (ह)",
			input:  "%u{939}",
			expect: "ह",
		},
		{
			name:   "%u{} Four digit code point (€)",
			input:  "%u{20AC}",
			expect: "€",
		},
		{
			name:   "%u{} Four digit code point (한)",
			input:  "%u{D55C}",
			expect: "한",
		},
		{
			name:   "%u{} Five digit code point (𐍈)",
			input:  "%u{10348}",
			expect: "𐍈",
		},
		{
			name:   "%u{} Left padded zeros",
			input:  "%u{000020}",
			expect: " ",
		},
		{
			name:   "%u{} Null byte",
			input:  "%u{0}",
			expect: "",
		},
		{
			name:   "%u{} Null byte terminates string",
			input:  "foo%u{0}bar",
			expect: "foo",
		},
		{
			name:   "%u{} Null byte terminates string",
			input:  "foo%u{000}bar",
			expect: "foo",
		},
		{
			name:    "%u{} Missing code point",
			input:   "%u{}",
			isError: true,
		},
		{
			name:    "%u{} Missing closing brace",
			input:   "%u{20",
			isError: true,
		},
		{
			name:    "%u{} Surrogate code point",
			input:   "%u{D800}",
			isError: true,
		},
		{
			name:    "%u{} Surrogate code point",
			input:   "%u{DFFF}",
			isError: true,
		},
		{
			name:    "%u{} Code point out of range",
			input:   "%u{FFFFFF}",
			isError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := decodeStringEscapes(tt.input)
			if tt.isError {
				if err == nil {
					t.Errorf("%s expects error but got nil", tt.name)
				}
				return
			}
			if err != nil {
				t.Errorf("%s unexpected error: %s", tt.name, err)
				return
			}
			if actual != tt.expect {
				t.Errorf("expect: \"%s\", actual: \"%s\"", tt.expect, actual)
			}
		})
	}
}
