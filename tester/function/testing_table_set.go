package function

import (
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/token"
)

const Testing_table_set_Name = "testing.table_set"

var Testing_table_set_ArgumentTypes = []value.Type{value.IdentType, value.StringType, value.StringType}

func Testing_table_set_Validate(args []value.Value) error {
	if len(args) != 3 {
		return errors.ArgumentNotEnough(Testing_table_set_Name, 3, args)
	}

	for i := range Testing_table_set_ArgumentTypes {
		if args[i].Type() != Testing_table_set_ArgumentTypes[i] {
			return errors.TypeMismatch(
				Testing_table_set_Name, i+1, Testing_table_set_ArgumentTypes[i], args[i].Type(),
			)
		}
	}
	return nil
}

func Testing_table_set(
	ctx *context.Context,
	args ...value.Value,
) (value.Value, error) {

	if err := Testing_table_set_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	tableName := value.Unwrap[*value.Ident](args[0]).Value
	// Check table existence
	v, ok := ctx.Tables[tableName]
	if !ok {
		return value.Null, errors.NewTestingError("table %s not found in VCL", tableName)
	}
	// Currently this function supports for STRING table,
	// common usecase for private edge dictionary.
	if v.ValueType != nil && v.ValueType.Value != "STRING" {
		return value.Null, errors.NewTestingError(
			"value type mismatch for table %s: expects %s, got %s",
			tableName,
			v.ValueType.Value,
			string(args[2].Type()),
		)
	}

	// Set Table value with virtual AST
	key := value.Unwrap[*value.String](args[1]).Value
	val := value.Unwrap[*value.String](args[2]).Value
	Testing_table_MergeProperty(v, &ast.TableProperty{
		Meta: &ast.Meta{
			Token: token.Null, // Null token for virtual AST
		},
		Key: &ast.String{
			Meta: &ast.Meta{
				Token: token.Token{Type: token.STRING, Literal: key},
			},
			Value: key,
		},
		Value: &ast.String{
			Meta: &ast.Meta{
				Token: token.Token{Type: token.STRING, Literal: val},
			},
			Value: val,
		},
	})

	return value.Null, nil
}
