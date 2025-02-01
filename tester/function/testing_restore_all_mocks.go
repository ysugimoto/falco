package function

import (
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Testing_restore_all_mocks_Name = "testing.restore_all_mocks"

func Testing_restore_all_mocks_Validate(args []value.Value) error {
	if len(args) > 0 {
		return errors.ArgumentMustEmpty(Testing_restore_all_mocks_Name, args)
	}
	return nil
}

func Testing_restore_all_mocks(
	ctx *context.Context,
	args ...value.Value,
) (value.Value, error) {

	if err := Testing_restore_all_mocks_Validate(args); err != nil {
		return nil, errors.NewTestingError("%s", err.Error())
	}

	// clear all mocked subroutines
	ctx.MockedSubroutines = map[string]*ast.SubroutineDeclaration{}
	ctx.MockedFunctioncalSubroutines = map[string]*ast.SubroutineDeclaration{}

	return value.Null, nil
}
