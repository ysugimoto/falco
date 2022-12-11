package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"go/format"
	"path/filepath"
	"text/template"

	"github.com/goccy/go-yaml"
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
	builtinInput  string
	builtinOutput string
}

func newInterpreter() *Interpreter {
	return &Interpreter{
		builtinInput:  "./builtin.yml",
		builtinOutput: "../interpreter/function/builtin_functions.go",
	}
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
		signature := fmt.Sprintf(
			"Call: func(ctx *context.Context, args ...value.Value) (value.Value, error) { return builtin.%s(ctx, args...) }",
			ucFirst(strings.ReplaceAll(key, ".", "_")),
		)
		buf.WriteString(signature + ",\n")
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
	tpl := template.Must(template.New("interpreter.function").Parse(interpreterFunctionImplementation))
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
