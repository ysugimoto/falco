//go:generate go run .

package main

import (
	"fmt"
)

var typeToType = map[string]string{
	"BOOL":    "types.BoolType",
	"INTEGER": "types.IntegerType",
	"FLOAT":   "types.FloatType",
	"STRING":  "types.StringType",
	"RTIME":   "types.RTimeType",
	"TIME":    "types.TimeType",
	"BACKEND": "types.BackendType",
	"IP":      "types.IPType",
	"ID":      "types.IDType",
	"ACL":     "types.AclType",
	"TABLE":   "types.TableType",
}

func main() {
	if err := newPredefinedGenerator().generate(); err != nil {
		panic(err)
	}

	if err := newBuiltinGenerator().generate(); err != nil {
		panic(err)
	}
}

func quote(v interface{}) string {
	return `"` + fmt.Sprint(v) + `"`
}
