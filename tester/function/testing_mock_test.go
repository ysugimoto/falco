package function

import (
	"testing"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

func Test_mock(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		mock    string
		isError bool
	}{
		{
			name: "mock subroutine",
			input: `sub original {
					set req.http.Original = "1";
				}`,
			mock: `sub mocked {
					set req.http.Mocked = "1";
				}`,
		},
		{
			name: "name mismatch",
			input: `sub undefined {
					set req.http.Original = "1";
				}`,
			mock: `sub mocked {
					set req.http.Mocked = "1";
				}`,
			isError: true,
		},
		{
			name: "cannot mock functional subroutine",
			input: `sub undefined STRING {
					set req.http.Original = "1";
					return "FOO";
				}`,
			mock: `sub mocked {
					set req.http.Mocked = "1";
				}`,
			isError: true,
		},
		{
			name: "cannot mock target functional subroutine",
			input: `sub original {
					set req.http.Original = "1";
				}`,
			mock: `sub mocked STRING {
					set req.http.Mocked = "1";
					return "FOO";
				}`,
			isError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			from, err := parser.New(lexer.NewFromString(tt.input)).ParseVCL()
			if err != nil {
				t.Errorf("Unexpected input parse error: %s", err)
				return
			}
			fromSubroutine := from.Statements[0].(*ast.SubroutineDeclaration)
			mock, err := parser.New(lexer.NewFromString(tt.mock)).ParseVCL()
			if err != nil {
				t.Errorf("Unexpected mock parse error: %s", err)
				return
			}
			mockSubroutine := mock.Statements[0].(*ast.SubroutineDeclaration)

			c := &context.Context{
				Subroutines: map[string]*ast.SubroutineDeclaration{
					fromSubroutine.Name.Value: fromSubroutine,
				},
				MockedSubroutines: map[string]*ast.SubroutineDeclaration{},
			}
			defs := &Definiions{
				Subroutines: map[string]*ast.SubroutineDeclaration{
					mockSubroutine.Name.Value: mockSubroutine,
				},
			}
			_, err = Testing_mock(
				c,
				defs,
				&value.String{Value: "original"},
				&value.String{Value: "mocked"},
			)
			if tt.isError {
				if err == nil {
					t.Errorf("Expected error but nil")
				}
				return
			}
			v, ok := c.MockedSubroutines["original"]
			if !ok {
				t.Errorf("Expected mocked subroutine exists but not found")
				return
			}
			if v.Name.Value != "mocked" {
				t.Errorf("Expected mocked subroutine exists but name is mismatch")
			}
		})
	}
}

func Test_mock_functional_subroutine(t *testing.T) {

	tests := []struct {
		name    string
		input   string
		mock    string
		isError bool
	}{
		{
			name: "mock functional subroutine",
			input: `sub original STRING {
					set req.http.Original = "1";
					return "FOO";
				}`,
			mock: `sub mocked STRING {
					set req.http.Mocked = "1";
					return "BAR";
				}`,
		},
		{
			name: "name mismatch",
			input: `sub undefined STRING {
					set req.http.Original = "1";
					return "FOO";
				}`,
			mock: `sub mocked STRING {
					set req.http.Mocked = "1";
					return "BAR";
				}`,
			isError: true,
		},
		{
			name: "cannot mock stateful subroutine",
			input: `sub undefined STRING {
					set req.http.Original = "1";
					return "FOO";
				}`,
			mock: `sub mocked {
					set req.http.Mocked = "1";
				}`,
			isError: true,
		},
		{
			name: "mock type mismatch",
			input: `sub original INTEGER {
					set req.http.Original = "1";
					return 1;
				}`,
			mock: `sub mocked STRING {
					set req.http.Mocked = "1";
					return "FOO";
				}`,
			isError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			from, err := parser.New(lexer.NewFromString(tt.input)).ParseVCL()
			if err != nil {
				t.Errorf("Unexpected input parse error: %s", err)
				return
			}
			fromSubroutine := from.Statements[0].(*ast.SubroutineDeclaration)
			mock, err := parser.New(lexer.NewFromString(tt.mock)).ParseVCL()
			if err != nil {
				t.Errorf("Unexpected mock parse error: %s", err)
				return
			}
			mockSubroutine := mock.Statements[0].(*ast.SubroutineDeclaration)

			c := &context.Context{
				SubroutineFunctions: map[string]*ast.SubroutineDeclaration{
					fromSubroutine.Name.Value: fromSubroutine,
				},
				MockedFunctioncalSubroutines: map[string]*ast.SubroutineDeclaration{},
			}
			defs := &Definiions{
				Subroutines: map[string]*ast.SubroutineDeclaration{
					mockSubroutine.Name.Value: mockSubroutine,
				},
			}
			_, err = Testing_mock(
				c,
				defs,
				&value.String{Value: "original"},
				&value.String{Value: "mocked"},
			)
			if tt.isError {
				if err == nil {
					t.Errorf("Expected error but nil")
				}
				return
			}
			v, ok := c.MockedFunctioncalSubroutines["original"]
			if !ok {
				t.Errorf("Expected mocked subroutine exists but not found")
				return
			}
			if v.Name.Value != "mocked" {
				t.Errorf("Expected mocked subroutine exists but name is mismatch")
			}
		})
	}
}

func Test_mock_fastly_reserved_subroutine(t *testing.T) {

	tests := []struct {
		name    string
		input   string
		mock    string
		isError bool
	}{
		{
			name: "cannot mock fastly reserved subroutine",
			input: `sub vcl_recv {
					set req.http.Original = "1";
				}`,
			mock: `sub mocked {
					set req.http.Mocked = "1";
				}`,
			isError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			from, err := parser.New(lexer.NewFromString(tt.input)).ParseVCL()
			if err != nil {
				t.Errorf("Unexpected input parse error: %s", err)
				return
			}
			fromSubroutine := from.Statements[0].(*ast.SubroutineDeclaration)
			mock, err := parser.New(lexer.NewFromString(tt.mock)).ParseVCL()
			if err != nil {
				t.Errorf("Unexpected mock parse error: %s", err)
				return
			}
			mockSubroutine := mock.Statements[0].(*ast.SubroutineDeclaration)

			c := &context.Context{
				Subroutines: map[string]*ast.SubroutineDeclaration{
					fromSubroutine.Name.Value: fromSubroutine,
				},
			}
			defs := &Definiions{
				Subroutines: map[string]*ast.SubroutineDeclaration{
					mockSubroutine.Name.Value: mockSubroutine,
				},
			}
			_, err = Testing_mock(
				c,
				defs,
				&value.String{Value: "vcl_recv"},
				&value.String{Value: "mocked"},
			)
			if tt.isError {
				if err == nil {
					t.Errorf("Expected error but nil")
				}
				return
			}
		})
	}
}
