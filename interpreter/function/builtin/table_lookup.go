// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Table_lookup_Name = "table.lookup"

var Table_lookup_ArgumentTypes = []value.Type{value.IdentType, value.StringType, value.StringType}

func Table_lookup_Validate(args []value.Value) error {
	if len(args) < 2 || len(args) > 3 {
		return errors.ArgumentNotInRange(Table_lookup_Name, 2, 3, args)
	}
	for i := range args {
		if args[i].Type() != Table_lookup_ArgumentTypes[i] {
			return errors.TypeMismatch(Table_lookup_Name, i+1, Table_lookup_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of table.lookup
// Arguments may be:
// - TABLE, STRING, STRING
// - TABLE, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/table/table-lookup/
func Table_lookup(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Table_lookup_Validate(args); err != nil {
		return value.Null, err
	}

	id := value.Unwrap[*value.Ident](args[0]).Value
	key := value.GetString(args[1]).String()
	defaultValue := &value.String{IsNotSet: true}
	if len(args) > 2 {
		// explicit clone value
		v := value.Unwrap[*value.String](args[2]).Value
		defaultValue = &value.String{Value: v}
	}

	table, ok := ctx.Tables[id]
	if !ok {
		return &value.String{IsNotSet: true}, errors.New(Table_lookup_Name,
			"table %d does not exist", id,
		)
	}

	for _, prop := range table.Properties {
		if prop.Key.Value == key {
			v, ok := prop.Value.(*ast.String)
			if !ok {
				return &value.String{IsNotSet: true}, errors.New(Table_lookup_Name,
					"table %s value could not cast to STRING type", id,
				)
			}
			return &value.String{Value: v.Value}, nil
		}
	}
	return defaultValue, nil
}
