// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"strings"
	"time"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Table_lookup_rtime_Name = "table.lookup_rtime"

var Table_lookup_rtime_ArgumentTypes = []value.Type{value.IdentType, value.StringType, value.RTimeType}

func Table_lookup_rtime_Validate(args []value.Value) error {
	if len(args) != 3 {
		return errors.ArgumentNotEnough(Table_lookup_rtime_Name, 3, args)
	}
	for i := range args {
		if args[i].Type() != Table_lookup_rtime_ArgumentTypes[i] {
			return errors.TypeMismatch(Table_lookup_rtime_Name, i+1, Table_lookup_rtime_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of table.lookup_rtime
// Arguments may be:
// - TABLE, STRING, RTIME
// Reference: https://developer.fastly.com/reference/vcl/functions/table/table-lookup-rtime/
func Table_lookup_rtime(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Table_lookup_rtime_Validate(args); err != nil {
		return value.Null, err
	}

	id := value.Unwrap[*value.Ident](args[0]).Value
	key := value.Unwrap[*value.String](args[1]).Value
	defaultValue := value.Unwrap[*value.RTime](args[2])

	table, ok := ctx.Tables[id]
	if !ok {
		return defaultValue, errors.New(Table_lookup_rtime_Name,
			"table %d does not exist", id,
		)
	}
	if table.ValueType == nil || table.ValueType.Value != "RTIME" {
		return defaultValue, errors.New(Table_lookup_rtime_Name,
			"table %d value type is not RTIME", id,
		)
	}

	for _, prop := range table.Properties {
		if prop.Key.Value != key {
			continue
		}

		v, ok := prop.Value.(*ast.RTime)
		if !ok {
			return defaultValue, errors.New(Table_lookup_rtime_Name,
				"table %s value could not cast to RTIME type", id,
			)
		}

		var val time.Duration
		switch {
		case strings.HasSuffix(v.Value, "d"):
			num := strings.TrimSuffix(v.Value, "d")
			val, _ = time.ParseDuration(num + "h")
			val *= 24
		case strings.HasSuffix(v.Value, "y"):
			num := strings.TrimSuffix(v.Value, "y")
			val, _ = time.ParseDuration(num + "h")
			val *= 24 * 365
		default:
			val, _ = time.ParseDuration(v.Value)
		}
		return &value.RTime{Value: val}, nil
	}
	return defaultValue.Copy(), nil
}
