package function

import (
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/token"
)

const Testing_table_define_Name = "testing.table_define"

func Testing_table_define_Validate(args []value.Value) error {
	if len(args) < 1 {
		return errors.ArgumentNotEnough(Testing_table_define_Name, 1, args)
	}

	if args[0].Type() != value.StringType {
		return errors.TypeMismatch(Testing_table_define_Name, 1, value.StringType, args[0].Type())
	}

	// Remaining arguments should be key-value pairs (even number of strings)
	if (len(args)-1)%2 != 0 {
		return errors.NewTestingError("testing.table_define expects table name followed by even number of key-value pairs")
	}

	for i := 1; i < len(args); i++ {
		if args[i].Type() != value.StringType {
			return errors.TypeMismatch(Testing_table_define_Name, i+1, value.StringType, args[i].Type())
		}
	}

	return nil
}

func Testing_table_define(
	ctx *context.Context,
	args ...value.Value,
) (value.Value, error) {

	if err := Testing_table_define_Validate(args); err != nil {
		return nil, errors.NewTestingError("%s", err.Error())
	}

	tableName := value.Unwrap[*value.String](args[0]).Value

	// Create a new table declaration
	table := &ast.TableDeclaration{
		Meta: &ast.Meta{
			Token: token.Null, // Null token for virtual AST
		},
		Name: &ast.Ident{
			Meta: &ast.Meta{
				Token: token.Token{Type: token.IDENT, Literal: tableName},
			},
			Value: tableName,
		},
		ValueType: &ast.Ident{
			Meta: &ast.Meta{
				Token: token.Token{Type: token.IDENT, Literal: "STRING"},
			},
			Value: "STRING",
		},
		Properties: []*ast.TableProperty{},
	}

	// Add key-value pairs
	for i := 1; i < len(args); i += 2 {
		key := value.Unwrap[*value.String](args[i]).Value
		val := value.Unwrap[*value.String](args[i+1]).Value

		prop := &ast.TableProperty{
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
		}

		table.Properties = append(table.Properties, prop)
	}

	// Add the table to the context
	ctx.Tables[tableName] = table

	return value.Null, nil
}