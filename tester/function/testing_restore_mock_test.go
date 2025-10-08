package function

import (
	"testing"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

func Test_restore_mock(t *testing.T) {
	tests := []struct {
		name     string
		mockName string
		mock     string
		isError  bool
	}{
		{
			name:     "restore mocked subroutine",
			mockName: "original",
			mock: `sub mocked {
					set req.http.Mocked = "1";
				}`,
		},
		{
			name:     "error if mocked subroutine not found",
			mockName: "undefined",
			mock: `sub mocked {
					set req.http.Mocked = "1";
				}`,
			isError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := parser.New(lexer.NewFromString(tt.mock)).ParseVCL()
			if err != nil {
				t.Errorf("Unexpected mock parse error: %s", err)
				return
			}
			mockSubroutine := mock.Statements[0].(*ast.SubroutineDeclaration)

			c := &context.Context{
				MockedSubroutines: map[string]*ast.SubroutineDeclaration{
					tt.mockName: mockSubroutine,
				},
			}
			_, err = Testing_restore_mock(
				c,
				&value.String{Value: "original"},
			)
			if tt.isError {
				if err == nil {
					t.Errorf("Expected error but nil")
				}
				return
			}
			_, ok := c.MockedSubroutines["original"]
			if ok {
				t.Errorf("Expected mocked subroutine does not exist but exists")
				return
			}
		})
	}
}

func Test_restore_functional_mock(t *testing.T) {

	tests := []struct {
		name     string
		mockName string
		mock     string
		isError  bool
	}{
		{
			name:     "mock functional subroutine",
			mockName: "original",
			mock: `sub mocked STRING {
					set req.http.Mocked = "1";
					return "BAR";
				}`,
		},
		{
			name:     "error if mocked functional subroutine not found",
			mockName: "undefined",
			mock: `sub mocked STRING {
					set req.http.Mocked = "1";
					return "BAR";
				}`,
			isError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := parser.New(lexer.NewFromString(tt.mock)).ParseVCL()
			if err != nil {
				t.Errorf("Unexpected mock parse error: %s", err)
				return
			}
			mockSubroutine := mock.Statements[0].(*ast.SubroutineDeclaration)

			c := &context.Context{
				MockedFunctioncalSubroutines: map[string]*ast.SubroutineDeclaration{
					tt.mockName: mockSubroutine,
				},
			}
			_, err = Testing_restore_mock(
				c,
				&value.String{Value: "original"},
			)
			if tt.isError {
				if err == nil {
					t.Errorf("Expected error but nil")
				}
				return
			}
			_, ok := c.MockedSubroutines["original"]
			if ok {
				t.Errorf("Expected mocked subroutine does not exist but exists")
				return
			}
		})
	}
}
