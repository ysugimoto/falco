package main

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"go/format"
	"text/template"

	"github.com/go-yaml/yaml"
)

type FunctionSpec struct {
	Arguments [][]string `yaml:"arguments"`
	Return    string     `yaml:"return"`
	Extra     string     `yaml:"extra"`
	On        []string   `yaml:"on"`
	Ref       string     `yaml:"reference"`
}

func (f *FunctionSpec) String() string {
	var buf bytes.Buffer

	buf.WriteString("&BuiltinFunction{\n")
	if f.Return != "" {
		buf.WriteString(fmt.Sprintf("Return: %s,\n", typeToType[f.Return]))
	}
	if f.Arguments != nil {
		buf.WriteString("Arguments: [][]types.Type{\n")
		for i := range f.Arguments {
			args := make([]string, len(f.Arguments[i]))
			for j, arg := range f.Arguments[i] {
				args[j] = typeToType[arg]
			}
			buf.WriteString(fmt.Sprintf("[]types.Type{%s},\n", strings.Join(args, ",")))
		}
		buf.WriteString("},\n")
	}
	switch f.Extra {
	case "LOOKUP_TABLE":
		buf.WriteString("Extra: func(c *Context, name string) interface{} { return c.Tables[name] },\n")
	}
	buf.WriteString(fmt.Sprintf("Scopes: %s,\n", strings.Join(f.On, "|")))
	buf.WriteString(fmt.Sprintf(`Reference: "%s"`+",\n", f.Ref))
	buf.WriteString("},\n")
	return buf.String()
}

type Builtin map[string]*FunctionSpec
type Spec struct {
	Items map[string]*Spec
	Value *FunctionSpec
}

type BuiltinGenerator struct {
	buf    bytes.Buffer
	input  string
	output string
}

func newBuiltinGenerator() *BuiltinGenerator {
	return &BuiltinGenerator{
		input:  "./builtin.yml",
		output: "../context/builtin.go",
	}
}

func (g *BuiltinGenerator) generate() error {
	fp, err := os.Open(g.input)
	if err != nil {
		return err
	}
	defer fp.Close()

	defs := Builtin{}
	if err := yaml.NewDecoder(fp).Decode(&defs); err != nil {
		return err
	}

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
			m = g.addOrSet(m, j)
		}
		m.Value = v
	}

	g.buf.WriteString("Functions{\n")
	for _, k := range g.keySort(fns) {
		v := fns[k]
		g.buf.WriteString(quote(k) + ": &FunctionSpec{\n")
		g.buf.WriteString("Items: map[string]*FunctionSpec{\n")
		g.generateSpec(v)
		g.buf.WriteString("},\n")
		if v.Value != nil {
			g.buf.WriteString("Value: ")
			g.buf.WriteString(v.Value.String())
		}
		g.buf.WriteString("},\n")
	}
	g.buf.WriteString("}\n")

	if err := g.writeToFile(); err != nil {
		return err
	}
	return nil
}

func (g *BuiltinGenerator) writeToFile() error {
	buf := new(bytes.Buffer)
	tpl := template.Must(template.New("builtin").Parse(builtinFunctions))
	if err := tpl.Execute(buf, map[string]interface{}{
		"Functions": g.buf.String(),
	}); err != nil {
		return err
	}

	ret, err := format.Source(buf.Bytes())
	if err != nil {
		return err
	}
	fp, err := os.OpenFile(g.output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer fp.Close()
	if _, err := fp.Write(ret); err != nil {
		return err
	}
	return nil
}

func (g *BuiltinGenerator) addOrSet(v *Spec, key string) *Spec {
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

func (g *BuiltinGenerator) generateSpec(s *Spec) {
	for _, k := range g.keySort(s.Items) {
		v := s.Items[k]
		g.buf.WriteString(quote(k) + ": &FunctionSpec{\n")
		g.buf.WriteString("Items: map[string]*FunctionSpec{\n")
		g.generateSpec(v)
		g.buf.WriteString("},\n")
		if v.Value != nil {
			g.buf.WriteString("Value: ")
			g.buf.WriteString(v.Value.String())
		}
		g.buf.WriteString("},\n")
	}
}

func (g *BuiltinGenerator) keySort(m map[string]*Spec) []string {
	keys := make([]string, 0, len(m))
	for k, _ := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	return keys
}
