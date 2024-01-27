package function

import (
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Testing_table_merge_Name = "testing.table_merge"

var Testing_table_merge_ArgumentTypes = []value.Type{value.IdentType, value.IdentType}

func Testing_table_merge_Validate(args []value.Value) error {
	if len(args) != 2 {
		return errors.ArgumentNotEnough(Testing_table_merge_Name, 3, args)
	}

	for i := range Testing_table_merge_ArgumentTypes {
		if args[i].Type() != Testing_table_merge_ArgumentTypes[i] {
			return errors.TypeMismatch(
				Testing_table_merge_Name, i+1, Testing_table_merge_ArgumentTypes[i], args[i].Type(),
			)
		}
	}
	return nil
}

func Testing_table_merge(
	ctx *context.Context,
	defs *Definiions,
	args ...value.Value,
) (value.Value, error) {

	if err := Testing_table_merge_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	baseTable := value.Unwrap[*value.Ident](args[0]).Value
	base, baseOK := ctx.Tables[baseTable]
	if !baseOK {
		return value.Null, errors.NewTestingError("table %s not found in VCL", baseTable)
	}
	mergeTable := value.Unwrap[*value.Ident](args[1]).Value
	merge, mergeOK := defs.Tables[mergeTable]
	if !mergeOK {
		return value.Null, errors.NewTestingError("table %s not found in testing VCL", mergeTable)
	}
	if err := Testing_table_merge_CompareType(base, merge); err != nil {
		return value.Null, err
	}

	// Merge table fields
	for i := range merge.Properties {
		Testing_table_MergeProperty(base, merge.Properties[i])
	}

	return value.Null, nil
}

func Testing_table_merge_CompareType(base, merge *ast.TableDeclaration) error {
	baseType := "STRING" // nolint: goconst
	if base.ValueType != nil {
		baseType = base.ValueType.Value
	}
	mergeType := "STRING" // nolint: goconst
	if merge.ValueType != nil {
		mergeType = merge.ValueType.Value
	}

	if baseType != mergeType {
		return errors.NewTestingError("table type mismatch. merge %s type into %s", mergeType, baseType)
	}
	return nil
}

func Testing_table_MergeProperty(base *ast.TableDeclaration, prop *ast.TableProperty) {
	for i := range base.Properties {
		// Check the same field name and replace it if found
		if base.Properties[i].Key.Value == prop.Key.Value {
			base.Properties[i] = prop
			return
		}
	}

	// Append property
	base.Properties = append(base.Properties, prop)
}
