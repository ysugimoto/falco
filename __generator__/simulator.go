package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"go/format"
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

type Simulator struct {
	predefinedInput  string
	predefinedOutput string
	builtinInput     string
	builtinOutput    string
}

func newSimulator() *Simulator {
	return &Simulator{
		predefinedInput:  "./predefined.yml",
		predefinedOutput: "../simulator/variable/predefined.go",
		builtinInput:     "./builtin.yml",
		builtinOutput:    "../simulator/function/function.go",
	}
}

func (s *Simulator) generatePredefined() error {
	fp, err := os.Open(s.predefinedInput)
	if err != nil {
		return err
	}
	defer fp.Close()

	defs := map[string]*Definition{}
	if err := yaml.NewDecoder(fp).Decode(&defs); err != nil {
		return err
	}

	var buf bytes.Buffer
	for _, key := range keySort[Definition](defs) {
		v := defs[key]
		keys := strings.Split(key, ".")
		var filtered []string
		var isAny bool
		for _, k := range keys {
			if k == "%any%" {
				isAny = true
				continue
			}
			filtered = append(filtered, k)
		}
		scope := generateScopeString(v.On)
		perm := generatePermissionString(v)
		buf.WriteString(fmt.Sprintf("vs.Predefined(\"%s\", %s, %s, %t)\n", strings.Join(filtered, "."), scope, perm, isAny))
	}

	out := new(bytes.Buffer)
	tpl := template.Must(template.New("simulator.predefined").Parse(simulatorPredefinedVariables))
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
	f, err := os.OpenFile(s.predefinedOutput, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(ret); err != nil {
		return err
	}
	return nil
}

func (s *Simulator) generateBuiltInFunction() error {
	fp, err := os.Open(s.builtinInput)
	if err != nil {
		return err
	}
	defer fp.Close()

	defs := map[string]*FunctionSpec{}
	if err := yaml.NewDecoder(fp).Decode(&defs); err != nil {
		return err
	}

	var buf bytes.Buffer
	for _, key := range keySort[FunctionSpec](defs) {
		v := defs[key]
		buf.WriteString(fmt.Sprintf("\"%s\": {\n", key))
		buf.WriteString(fmt.Sprintf("Scope: %s,\n", generateScopeString(v.On)))
		// TODO: implement all builtin functions
		// buf.WriteString(fmt.Sprintf("Call: %s,\n", strings.ReplaceAll(key, ".", "_")))
		buf.WriteString("Call: func(ctx *context.Context, args ...variable.Value) (variable.Value, error) { return variable.Null, nil },\n")
		buf.WriteString("},\n")
	}

	out := new(bytes.Buffer)
	tpl := template.Must(template.New("simulator.builtin").Parse(simulatorBuiltinFunctions))
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
	f, err := os.OpenFile(s.builtinOutput, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(ret); err != nil {
		return err
	}
	return nil
}

func generateScopeString(on []string) string {
	out := make([]string, len(on))
	for i := range on {
		out[i] = fmt.Sprintf("types.%s", scopeMap[on[i]])
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
