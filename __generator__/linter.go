package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"go/format"
	"text/template"

	"gopkg.in/yaml.v3"
)

type Linter struct {
	predefinedInput  string
	predefinedOutput string
	builtinInput     string
	builtinOutput    string
}

func newLinter() *Linter {
	return &Linter{
		predefinedInput:  "./predefined.yml",
		predefinedOutput: "../linter/context/predefined.go",
		builtinInput:     "./builtin.yml",
		builtinOutput:    "../linter/context/builtin.go",
	}
}

func (l *Linter) generatePredefined() error {
	fp, err := os.Open(l.predefinedInput)
	if err != nil {
		return err
	}
	defer fp.Close()

	defs := map[string]*Definition{}
	if err := yaml.NewDecoder(fp).Decode(&defs); err != nil {
		return err
	}

	var buf bytes.Buffer
	vars := map[string]*Object{}

	for k, v := range defs {
		spl := strings.Split(k, ".")
		first, remains := spl[0], spl[1:]
		m, ok := vars[first]
		if !ok {
			m = &Object{
				Items: make(map[string]*Object),
			}
			vars[first] = m
		}
		for _, j := range remains {
			m = addOrSetObject(m, j)
		}
		m.Value = v
	}

	buf.WriteString("Variables{\n")
	for _, k := range keySort[Object](vars) {
		v := vars[k]
		buf.WriteString(quote(k) + ": &Object{\n")
		buf.WriteString("Items: map[string]*Object{\n")
		l.generateObject(&buf, v)
		buf.WriteString("},\n")
		if v.Value != nil {
			buf.WriteString("Value: ")
			buf.WriteString(v.Value.String())
		}
		buf.WriteString("},\n")
	}
	buf.WriteString("}\n")

	out := new(bytes.Buffer)
	tpl := template.Must(template.New("linter.predefined").Parse(linterPredefinedVariables))
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
	f, err := os.OpenFile(l.predefinedOutput, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(ret); err != nil {
		return err
	}
	return nil
}

func (l *Linter) generateBuiltInFunction() error {
	fp, err := os.Open(l.builtinInput)
	if err != nil {
		return err
	}
	defer fp.Close()

	defs := map[string]*FunctionSpec{}
	if err := yaml.NewDecoder(fp).Decode(&defs); err != nil {
		return err
	}

	var buf bytes.Buffer
	fns := map[string]*Spec{}

	for k, v := range defs {
		spl := strings.Split(k, ".")
		first, remains := spl[0], spl[1:]
		m, ok := fns[first]
		if !ok {
			m = &Spec{
				Items: make(map[string]*Spec),
			}
			fns[first] = m
		}
		for _, j := range remains {
			m = addOrSetSpec(m, j)
		}
		m.Value = v
	}

	buf.WriteString("Functions{\n")
	for _, k := range keySort[Spec](fns) {
		v := fns[k]
		buf.WriteString(quote(k) + ": &FunctionSpec{\n")
		buf.WriteString("Items: map[string]*FunctionSpec{\n")
		l.generateSpec(&buf, v)
		buf.WriteString("},\n")
		if v.Value != nil {
			buf.WriteString("Value: ")
			buf.WriteString(v.Value.String())
		}
		buf.WriteString("},\n")
	}
	buf.WriteString("}\n")

	out := new(bytes.Buffer)
	tpl := template.Must(template.New("linter.builtin").Parse(linterBuiltinFunctions))
	if err := tpl.Execute(out, map[string]interface{}{
		"Functions": buf.String(),
	}); err != nil {
		return err
	}

	ret, err := format.Source(out.Bytes())
	if err != nil {
		return err
	}
	f, err := os.OpenFile(l.builtinOutput, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(ret); err != nil {
		return err
	}
	return nil
}

func (l *Linter) generateSpec(buf *bytes.Buffer, s *Spec) {
	for _, k := range keySort[Spec](s.Items) {
		v := s.Items[k]
		buf.WriteString(quote(k) + ": &FunctionSpec{\n")
		buf.WriteString("Items: map[string]*FunctionSpec{\n")
		l.generateSpec(buf, v)
		buf.WriteString("},\n")
		if v.Value != nil {
			buf.WriteString("Value: ")
			buf.WriteString(v.Value.String())
		}
		buf.WriteString("},\n")
	}
}

func (l *Linter) generateObject(buf *bytes.Buffer, value *Object) {
	for _, k := range keySort[Object](value.Items) {
		v := value.Items[k]
		buf.WriteString(quote(k) + ": {\n")
		buf.WriteString("Items: map[string]*Object{\n")
		l.generateObject(buf, v)
		buf.WriteString("},\n")
		if v.Value != nil {
			buf.WriteString("Value: ")
			buf.WriteString(v.Value.String())
		}
		buf.WriteString("},\n")
	}
}

func addOrSetSpec(v *Spec, key string) *Spec {
	var o *Spec
	vo := *v
	if val, ok := vo.Items[key]; !ok {
		o = &Spec{
			Items: make(map[string]*Spec),
		}
		v.Items[key] = o
	} else {
		o = val
	}
	return o
}

func addOrSetObject(v *Object, key string) *Object {
	var o *Object
	vo := *v
	if val, ok := vo.Items[key]; !ok {
		o = &Object{
			Items: make(map[string]*Object),
		}
		v.Items[key] = o
	} else {
		o = val
	}
	return o
}
