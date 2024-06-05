package function

import (
	"testing"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

func Test_restore_all_mocks(t *testing.T) {

	tests := []struct {
		name string
		mock string
	}{
		{
			name: "restore mocked subroutine",
			mock: `sub mocked {
					set req.http.Mocked = "1";
				}`,
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
					"original": mockSubroutine,
				},
			}
			_, err = Testing_restore_all_mocks(c)
			if err != nil {
				t.Errorf("Expected no error but returned: %s", err)
			}
			if len(c.MockedSubroutines) > 0 {
				t.Errorf("mocked subroutines must be empty")
			}
			if len(c.MockedFunctioncalSubroutines) > 0 {
				t.Errorf("mocked functional subroutines must be empty")
			}
		})
	}
}

func Test_restore_all_functional_mock(t *testing.T) {

	tests := []struct {
		name    string
		mock    string
		isError bool
	}{
		{
			name: "restore mocked functional subroutine",
			mock: `sub mocked STRING {
					set req.http.Mocked = "1";
					return "BAR";
				}`,
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
					"original": mockSubroutine,
				},
			}
			_, err = Testing_restore_all_mocks(c)
			if err != nil {
				t.Errorf("Expected no error but returned: %s", err)
			}
			if len(c.MockedSubroutines) > 0 {
				t.Errorf("mocked subroutines must be empty")
			}
			if len(c.MockedFunctioncalSubroutines) > 0 {
				t.Errorf("mocked functional subroutines must be empty")
			}
		})
	}
}
