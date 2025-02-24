package interpreter

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/tester/shared"
	"github.com/ysugimoto/falco/token"
)

var opts = cmp.Options{
	cmpopts.IgnoreFields(
		ast.Meta{},
		"Token", "ID", "Leading", "Trailing", "Infix",
		"Nest", "PreviousEmptyLines", "EndLine", "EndPosition",
	),
}

type testTable struct {
	name     string
	input    string
	expect   string
	coverage *shared.CoverageFactory
}
type testTables []testTable

func assertInstrument(t *testing.T, tests testTables) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vcl, err := parser.New(lexer.NewFromString(tt.input)).ParseVCL()
			if err != nil {
				t.Errorf("Unexpected input VCL parse error: %s", err)
				return
			}
			c := shared.NewCoverage()
			ip := &Interpreter{
				ctx: context.New(context.WithCoverage(c)),
			}
			ip.instrument(vcl)

			expect, err := parser.New(lexer.NewFromString(tt.expect)).ParseVCL()
			if err != nil {
				t.Errorf("Unexpected expect VCL parse error: %s", err)
				return
			}
			if diff := cmp.Diff(vcl, expect, opts...); diff != "" {
				t.Errorf("instrumented vcl mismatch, diff=%s", diff)
				return
			}
			if diff := cmp.Diff(c.Factory(), tt.coverage); diff != "" {
				t.Errorf("coverage state mismatch, diff=%s", diff)
				return
			}
		})
	}
}

func TestInstrumentSubroutine(t *testing.T) {
	tests := testTables{
		{
			name: "subroutine instrumenting",
			input: `
sub instrument1 {
	set req.http.Foo = "bar";
}
sub instrument2 {
	set req.http.Bar = "baz";
}
`,
			expect: `
sub instrument1 {
	coverage.subroutine("sub_2_1");
	coverage.statement("stmt_3_2");
	set req.http.Foo = "bar";
}
sub instrument2 {
	coverage.subroutine("sub_5_1");
	coverage.statement("stmt_6_2");
	set req.http.Bar = "baz";
}
`,
			coverage: &shared.CoverageFactory{
				Subroutines: shared.CoverageFactoryItem{
					"sub_2_1": 0,
					"sub_5_1": 0,
				},
				Statements: shared.CoverageFactoryItem{
					"stmt_3_2": 0,
					"stmt_6_2": 0,
				},
				Branches: shared.CoverageFactoryItem{},
				NodeMap: map[string]token.Token{
					"sub_2_1":  {Type: token.SUBROUTINE, Literal: "sub", Line: 2, Position: 1},
					"sub_5_1":  {Type: token.SUBROUTINE, Literal: "sub", Line: 5, Position: 1},
					"stmt_3_2": {Type: token.SET, Literal: "set", Line: 3, Position: 2},
					"stmt_6_2": {Type: token.SET, Literal: "set", Line: 6, Position: 2},
				},
			},
		},
	}
	assertInstrument(t, tests)
}

func TestInstrumentIfStatement(t *testing.T) {
	tests := testTables{
		{
			name: "if statement instrumenting",
			input: `
sub instrument {
	declare local var.V STRING;
	if (req.http.Foo) {
		set var.V = req.http.Foo;
	} else if (req.http.Bar) {
		set var.V = req.http.Bar;
	} elsif (req.http.Baz) {
		set var.V = req.http.Bar;
	} else {
		if (req.http.Other) {
			set var.V = "other";
		} else {
			set var.V = "unknown";
		}
	}
	set req.http.V = var.V;
}
`,
			expect: `
sub instrument {
	coverage.subroutine("sub_2_1");
	coverage.statement("stmt_3_2");
	declare local var.V STRING;
	coverage.statement("stmt_4_2");
	if (req.http.Foo) {
		coverage.branch("branch_4_2_1");
		coverage.statement("stmt_5_3");
		set var.V = req.http.Foo;
	} else {
		coverage.branch("branch_4_2_2");
		if (req.http.Bar) {
			coverage.branch("branch_6_9_1");
			coverage.statement("stmt_7_3");
			set var.V = req.http.Bar;
		} else {
			coverage.branch("branch_4_2_3");
			if (req.http.Baz) {
				coverage.branch("branch_8_4_1");
				coverage.statement("stmt_9_3");
				set var.V = req.http.Bar;
			} else {
				coverage.branch("branch_4_2_4");
				coverage.statement("stmt_11_3");
				if (req.http.Other) {
					coverage.branch("branch_11_3_1");
					coverage.statement("stmt_12_4");
					set var.V = "other";
				} else {
					coverage.branch("branch_11_3_2");
					coverage.statement("stmt_14_4");
					set var.V = "unknown";
				}
			}
		}
	}
	coverage.statement("stmt_17_2");
	set req.http.V = var.V;
}
`,
			coverage: &shared.CoverageFactory{
				Subroutines: shared.CoverageFactoryItem{
					"sub_2_1": 0,
				},
				Statements: shared.CoverageFactoryItem{
					"stmt_3_2":  0,
					"stmt_4_2":  0,
					"stmt_5_3":  0,
					"stmt_7_3":  0,
					"stmt_9_3":  0,
					"stmt_11_3": 0,
					"stmt_12_4": 0,
					"stmt_14_4": 0,
					"stmt_17_2": 0,
				},
				Branches: shared.CoverageFactoryItem{
					"branch_4_2_1":  0,
					"branch_4_2_2":  0,
					"branch_4_2_3":  0,
					"branch_4_2_4":  0,
					"branch_6_9_1":  0,
					"branch_8_4_1":  0,
					"branch_11_3_1": 0,
					"branch_11_3_2": 0,
				},
				NodeMap: map[string]token.Token{
					"sub_2_1":       {Type: token.SUBROUTINE, Literal: "sub", Line: 2, Position: 1},
					"stmt_3_2":      {Type: token.DECLARE, Literal: "declare", Line: 3, Position: 2},
					"stmt_4_2":      {Type: token.IF, Literal: "if", Line: 4, Position: 2},
					"stmt_5_3":      {Type: token.SET, Literal: "set", Line: 5, Position: 3},
					"stmt_7_3":      {Type: token.SET, Literal: "set", Line: 7, Position: 3},
					"stmt_9_3":      {Type: token.SET, Literal: "set", Line: 9, Position: 3},
					"stmt_11_3":     {Type: token.IF, Literal: "if", Line: 11, Position: 3},
					"stmt_12_4":     {Type: token.SET, Literal: "set", Line: 12, Position: 4},
					"stmt_14_4":     {Type: token.SET, Literal: "set", Line: 14, Position: 4},
					"stmt_17_2":     {Type: token.SET, Literal: "set", Line: 17, Position: 2},
					"branch_4_2_1":  {Type: token.IF, Literal: "if", Line: 4, Position: 2},
					"branch_4_2_2":  {Type: token.IF, Literal: "if", Line: 4, Position: 2},
					"branch_4_2_3":  {Type: token.IF, Literal: "if", Line: 4, Position: 2},
					"branch_4_2_4":  {Type: token.IF, Literal: "if", Line: 4, Position: 2},
					"branch_6_9_1":  {Type: token.IF, Literal: "if", Line: 6, Position: 9},
					"branch_8_4_1":  {Type: token.ELSIF, Literal: "elsif", Line: 8, Position: 4},
					"branch_11_3_1": {Type: token.IF, Literal: "if", Line: 11, Position: 3},
					"branch_11_3_2": {Type: token.IF, Literal: "if", Line: 11, Position: 3},
				},
			},
		},
	}
	assertInstrument(t, tests)
}

func TestInstrumentSwitchStatement(t *testing.T) {
	tests := testTables{
		{
			name: "switch statement instrumenting",
			input: `
sub instrument {
	declare local var.V STRING;
	switch (req.http.Item) {
	case "1":
		set var.V = "foo";
		break;
	case "2":
		set var.V = "bar";
		break;
	case "3":
		set var.V = "baz";
		fallthrough;
	default:
		set var.V = "unknown";
		break;
	}
}
`,
			expect: `
sub instrument {
	coverage.subroutine("sub_2_1");
	coverage.statement("stmt_3_2");
	declare local var.V STRING;
	coverage.statement("stmt_4_2");
	switch (req.http.Item) {
	case "1":
		coverage.branch("branch_4_2_1");
		coverage.branch("branch_5_2");
		coverage.statement("stmt_6_3");
		set var.V = "foo";
		coverage.statement("stmt_7_3");
		break;
	case "2":
		coverage.branch("branch_4_2_2");
		coverage.branch("branch_8_2");
		coverage.statement("stmt_9_3");
		set var.V = "bar";
		coverage.statement("stmt_10_3");
		break;
	case "3":
		coverage.branch("branch_4_2_3");
		coverage.branch("branch_11_2");
		coverage.statement("stmt_12_3");
		set var.V = "baz";
		coverage.statement("stmt_13_3");
		fallthrough;
	default:
		coverage.branch("branch_4_2_4");
		coverage.branch("branch_14_2");
		coverage.statement("stmt_15_3");
		set var.V = "unknown";
		coverage.statement("stmt_16_3");
		break;
	}
}
`,
			coverage: &shared.CoverageFactory{
				Subroutines: shared.CoverageFactoryItem{
					"sub_2_1": 0,
				},
				Statements: shared.CoverageFactoryItem{
					"stmt_3_2":  0,
					"stmt_4_2":  0,
					"stmt_6_3":  0,
					"stmt_7_3":  0,
					"stmt_9_3":  0,
					"stmt_10_3": 0,
					"stmt_12_3": 0,
					"stmt_13_3": 0,
					"stmt_15_3": 0,
					"stmt_16_3": 0,
				},
				Branches: shared.CoverageFactoryItem{
					"branch_4_2_1": 0,
					"branch_4_2_2": 0,
					"branch_4_2_3": 0,
					"branch_4_2_4": 0,
					"branch_5_2":   0,
					"branch_8_2":   0,
					"branch_11_2":  0,
					"branch_14_2":  0,
				},
				NodeMap: map[string]token.Token{
					"sub_2_1":      {Type: token.SUBROUTINE, Literal: "sub", Line: 2, Position: 1},
					"stmt_3_2":     {Type: token.DECLARE, Literal: "declare", Line: 3, Position: 2},
					"stmt_4_2":     {Type: token.SWITCH, Literal: "switch", Line: 4, Position: 2},
					"stmt_6_3":     {Type: token.SET, Literal: "set", Line: 6, Position: 3},
					"stmt_7_3":     {Type: token.BREAK, Literal: "break", Line: 7, Position: 3},
					"stmt_9_3":     {Type: token.SET, Literal: "set", Line: 9, Position: 3},
					"stmt_10_3":    {Type: token.BREAK, Literal: "break", Line: 10, Position: 3},
					"stmt_12_3":    {Type: token.SET, Literal: "set", Line: 12, Position: 3},
					"stmt_13_3":    {Type: token.FALLTHROUGH, Literal: "fallthrough", Line: 13, Position: 3},
					"stmt_15_3":    {Type: token.SET, Literal: "set", Line: 15, Position: 3},
					"stmt_16_3":    {Type: token.BREAK, Literal: "break", Line: 16, Position: 3},
					"branch_4_2_1": {Type: token.SWITCH, Literal: "switch", Line: 4, Position: 2},
					"branch_4_2_2": {Type: token.SWITCH, Literal: "switch", Line: 4, Position: 2},
					"branch_4_2_3": {Type: token.SWITCH, Literal: "switch", Line: 4, Position: 2},
					"branch_4_2_4": {Type: token.SWITCH, Literal: "switch", Line: 4, Position: 2},
					"branch_5_2":   {Type: token.CASE, Literal: "case", Line: 5, Position: 2},
					"branch_8_2":   {Type: token.CASE, Literal: "case", Line: 8, Position: 2},
					"branch_11_2":  {Type: token.CASE, Literal: "case", Line: 11, Position: 2},
					"branch_14_2":  {Type: token.DEFAULT, Literal: "default", Line: 14, Position: 2},
				},
			},
		},
	}
	assertInstrument(t, tests)
}

func TestInstrumentIfExpression(t *testing.T) {
	tests := testTables{
		{
			name: "if expression instrumenting",
			input: `
sub instrument {
	declare local var.V STRING;
	set var.V = if(req.http.Foo, "bar", "baz");
}
`,
			expect: `
sub instrument {
	coverage.subroutine("sub_2_1");
	coverage.statement("stmt_3_2");
	declare local var.V STRING;
	coverage.statement("stmt_4_2");
	if (req.http.Foo) {
		coverage.branch("branch_4_14_true");
	} else {
		coverage.branch("branch_4_14_false");
	}
	set var.V = if(req.http.Foo, "bar", "baz");
}
`,
			coverage: &shared.CoverageFactory{
				Subroutines: shared.CoverageFactoryItem{
					"sub_2_1": 0,
				},
				Statements: shared.CoverageFactoryItem{
					"stmt_3_2": 0,
					"stmt_4_2": 0,
				},
				Branches: shared.CoverageFactoryItem{
					"branch_4_14_true":  0,
					"branch_4_14_false": 0,
				},
				NodeMap: map[string]token.Token{
					"sub_2_1":           {Type: token.SUBROUTINE, Literal: "sub", Line: 2, Position: 1},
					"stmt_3_2":          {Type: token.DECLARE, Literal: "declare", Line: 3, Position: 2},
					"stmt_4_2":          {Type: token.SET, Literal: "set", Line: 4, Position: 2},
					"branch_4_14_true":  {Type: token.IF, Literal: "if", Line: 4, Position: 14},
					"branch_4_14_false": {Type: token.IF, Literal: "if", Line: 4, Position: 14},
				},
			},
		},
	}
	assertInstrument(t, tests)
}
