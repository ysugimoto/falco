package main

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"go/format"
	"path/filepath"
	"text/template"

	"github.com/go-yaml/yaml"
)

var scopeMap = map[string]string{
	"RECV":    "RecvScope",
	"HASH":    "HashScope",
	"HIT":     "HitScope",
	"MISS":    "MissScope",
	"PASS":    "PassScope",
	"FETCH":   "FetchScope",
	"ERROR":   "ErrorScope",
	"DELIVER": "DeliverScope",
	"LOG":     "LogScope",
}

const packagePath = "github.com/ysugimoto/falco/interpreter/function/"

type Interpreter struct {
	builtinInput     string
	builtinOutput    string
	predefinedInput  string
	predefinedOutput string
}

func newInterpreter() *Interpreter {
	return &Interpreter{
		builtinInput:     "./builtin.yml",
		builtinOutput:    "../interpreter/function/builtin_functions.go",
		predefinedInput:  "./predefined.yml",
		predefinedOutput: "../interpreter/variable/predfined.go",
	}
}

func (i *Interpreter) generatePredefined() error {
	fp, err := os.Open(i.predefinedInput)
	if err != nil {
		return err
	}
	defer fp.Close()

	defs := map[string]*Definition{}
	if err := yaml.NewDecoder(fp).Decode(&defs); err != nil {
		return err
	}

	// Interpreter only wants variable names as constant
	var variables []string
	for key := range defs {
		if strings.Contains(key, "%") {
			continue
		}
		variables = append(variables, key)
	}

	sort.Strings(variables)

	var buf bytes.Buffer
	for _, v := range variables {
		buf.WriteString(fmt.Sprintf("%s = \"%s\"\n", strings.ToUpper(strings.ReplaceAll(v, ".", "_")), v))
	}

	out := new(bytes.Buffer)
	tpl := template.Must(template.New("interpreter.predefined").Parse(interpreterPredefinedVariables))
	if err := tpl.Execute(out, map[string]interface{}{
		"Variables": buf.String(),
	}); err != nil {
		return err
	}

	ret, err := format.Source(out.Bytes())
	if err != nil {
		fmt.Println(buf.String())
		return err
	}
	f, err := os.OpenFile(i.predefinedOutput, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(ret); err != nil {
		return err
	}
	return nil
}

func (i *Interpreter) generateBuiltInFunction() error {
	fp, err := os.Open(i.builtinInput)
	if err != nil {
		return err
	}
	defer fp.Close()

	defs := map[string]*FunctionSpec{}
	if err := yaml.NewDecoder(fp).Decode(&defs); err != nil {
		return err
	}

	if _, err := os.Stat("../interpreter/function/builtin"); err != nil {
		os.Mkdir("../interpreter/function/builtin", 0755)
	}

	var buf bytes.Buffer
	for _, key := range keySort[FunctionSpec](defs) {
		v := defs[key]
		buf.WriteString(fmt.Sprintf("\"%s\": {\n", key))
		buf.WriteString(fmt.Sprintf("Scope: %s,\n", generateScopeString(v.On)))
		if err := i.generateBuiltInFunctionFile(key, v); err != nil {
			return err
		}
		if err := i.generateBuiltInFunctionTestFile(key, v); err != nil {
			return err
		}
		signature := fmt.Sprintf(
			"Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) { return builtin.%s(ctx, args...) }",
			ucFirst(strings.ReplaceAll(key, ".", "_")),
		)
		buf.WriteString(signature + ",\n")
		buf.WriteString(fmt.Sprintf("CanStatementCall: %t,\n", v.Return == ""))
		buf.WriteString("IsIdentArgument: func(i int) bool {\n")
		buf.WriteString(fmt.Sprintf("return %s\n", i.createFunctionIdentArguments(v.Arguments)))
		buf.WriteString("},\n")
		buf.WriteString("},\n")
	}

	out := new(bytes.Buffer)
	tpl := template.Must(template.New("interpreter.builtin").Parse(interpreterBuiltinFunctions))
	if err := tpl.Execute(out, map[string]interface{}{
		"Functions": buf.String(),
	}); err != nil {
		return err
	}

	ret, err := format.Source(out.Bytes())
	if err != nil {
		fmt.Println(buf.String())
		return err
	}
	f, err := os.OpenFile(i.builtinOutput, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(ret); err != nil {
		return err
	}
	return nil
}

func (i *Interpreter) createFunctionIdentArguments(arguments [][]string) string {
	// Find max length of arguments
	var maxArgs []string
	for _, args := range arguments {
		if len(args) > len(maxArgs) {
			maxArgs = args
		}
	}

	var codes []string
	// Find ID type argument position
	for i, arg := range maxArgs {
		if arg == "ID" {
			codes = append(codes, fmt.Sprintf("i == %d", i))
		}
	}

	if len(codes) == 0 {
		return "false"
	}
	return strings.Join(codes, " || ")
}

func (i *Interpreter) generateBuiltInFunctionFile(name string, fn *FunctionSpec) error {
	filename := fmt.Sprintf("%s.go", strings.ReplaceAll(name, ".", "_"))
	path := filepath.Join("../interpreter/function/builtin", filename)

	if _, err := os.Stat(path); err == nil {
		// already generated
		return nil
	}
	fp, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer fp.Close()

	var args []string
	for j := range fn.Arguments {
		args = append(args, strings.Join(fn.Arguments[j], ", "))
	}

	out := new(bytes.Buffer)
	tpl := template.Must(
		template.New("interpreter.function").
			Parse(interpreterFunctionImplementation),
	)
	if err := tpl.Execute(out, map[string]interface{}{
		"Name":          ucFirst(strings.ReplaceAll(name, ".", "_")),
		"Original":      name,
		"Reference":     fn.Ref,
		"Arguments":     args,
		"Return":        fn.Return,
		"MinArgs":       minArgs(fn.Arguments),
		"MaxArgs":       maxArgs(fn.Arguments),
		"ArgumentTypes": argumentTypes(fn.Arguments),
		"NoArgument":    len(fn.Arguments) == 0,
	}); err != nil {
		return err
	}

	ret, err := format.Source(out.Bytes())
	if err != nil {
		fmt.Println(out.String())
		return err
	}
	if _, err := fp.Write(ret); err != nil {
		return err
	}
	return nil
}

func (i *Interpreter) generateBuiltInFunctionTestFile(name string, fn *FunctionSpec) error {
	filename := fmt.Sprintf("%s_test.go", strings.ReplaceAll(name, ".", "_"))
	path := filepath.Join("../interpreter/function/builtin", filename)

	if _, err := os.Stat(path); err == nil {
		// already generated
		return nil
	}
	fp, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer fp.Close()

	var args []string
	for j := range fn.Arguments {
		args = append(args, strings.Join(fn.Arguments[j], ", "))
	}

	out := new(bytes.Buffer)
	tpl := template.Must(template.New("interpreter.function").Parse(interpreterFunctionTestImplementation))
	if err := tpl.Execute(out, map[string]interface{}{
		"Name":      ucFirst(strings.ReplaceAll(name, ".", "_")),
		"Original":  name,
		"Reference": fn.Ref,
		"Arguments": args,
		"Return":    fn.Return,
	}); err != nil {
		return err
	}

	ret, err := format.Source(out.Bytes())
	if err != nil {
		fmt.Println(out.String())
		return err
	}
	if _, err := fp.Write(ret); err != nil {
		return err
	}
	return nil
}

func ucFirst(str string) string {
	b := []byte(str)
	b[0] -= 0x20
	return string(b)
}

func generateScopeString(on []string) string {
	out := make([]string, len(on))
	for i := range on {
		out[i] = fmt.Sprintf("context.%s", scopeMap[on[i]])
	}
	return strings.Join(out, "|")
}

func generatePermissionString(v *Definition) string {
	var out []string
	if v.Get != "" {
		out = append(out, "types.PermissionGet")
	}
	if v.Set != "" {
		out = append(out, "types.PermissionSet")
	}
	if v.Unset {
		out = append(out, "types.PermissionUnset")
	}
	return strings.Join(out, "|")
}

func minArgs(args [][]string) int {
	if len(args) == 0 {
		return 0
	}
	size := len(args[0])
	for i := 1; i < len(args); i++ {
		if len(args[i]) < size {
			size = len(args[i])
		}
	}
	return size
}

func maxArgs(args [][]string) int {
	size := 0
	for i := 0; i < len(args); i++ {
		if len(args[i]) > size {
			size = len(args[i])
		}
	}
	return size
}

// Type map builtin definition corresponds to value.Type string
var typeMap = map[string]string{
	"ID":      "value.IdentType",
	"TABLE":   "value.IdentType",
	"STRING":  "value.StringType",
	"IP":      "value.IpType",
	"BOOLEAN": "value.BooleanType",
	"INTEGER": "value.IntegerType",
	"FLOAT":   "value.FloatType",
	"RTIME":   "value.RTimeType",
	"TIME":    "value.TimeType",
	"BACKEND": "value.BackendType",
	"ACL":     "value.AclType",
}

func argumentTypes(args [][]string) string {
	var maxArgs []string
	for i := 0; i < len(args); i++ {
		if len(args[i]) > len(maxArgs) {
			maxArgs = args[i]
		}
	}
	types := make([]string, len(maxArgs))
	for i := range maxArgs {
		types[i] = typeMap[maxArgs[i]]
	}
	return fmt.Sprintf("[]value.Type{%s}", strings.Join(types, ", "))
}
