//go:generate go run .

package main

import (
	"fmt"
	"sort"
)

var typeToType = map[string]string{
	"BOOL":        "types.BoolType",
	"INTEGER":     "types.IntegerType",
	"FLOAT":       "types.FloatType",
	"STRING":      "types.StringType",
	"RTIME":       "types.RTimeType",
	"TIME":        "types.TimeType",
	"BACKEND":     "types.BackendType",
	"REQBACKEND":  "types.ReqBackendType",
	"IP":          "types.IPType",
	"ID":          "types.IDType",
	"ACL":         "types.AclType",
	"TABLE":       "types.TableType",
	"STRING_LIST": "types.StringListType",
}

func main() {
	l := newLinter()
	if err := l.generatePredefined(); err != nil {
		panic(err)
	}

	if err := l.generateBuiltInFunction(); err != nil {
		panic(err)
	}

	i := newInterpreter()
	if err := i.generatePredefined(); err != nil {
		panic(err)
	}
	if err := i.generateBuiltInFunction(); err != nil {
		panic(err)
	}

	c := newConsole()
	if err := c.generateSuggestions(); err != nil {
		panic(err)
	}
}

func quote(v interface{}) string {
	return `"` + fmt.Sprint(v) + `"`
}

func keySort[T Spec | Object | Definition | FunctionSpec](m map[string]*T) []string {
	keys := make([]string, 0, len(m))
	for k, _ := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	return keys
}
