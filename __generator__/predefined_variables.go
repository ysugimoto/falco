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

type Definition struct {
	Get   string   `yaml:"get"`
	Set   string   `yaml:"set"`
	Unset bool     `yaml:"unset"`
	On    []string `yaml:"on"`
	Ref   string   `yaml:"reference"`
}

func (d *Definition) String() string {
	var buf bytes.Buffer

	buf.WriteString("&Accessor{\n")
	if d.Get != "" {
		buf.WriteString(fmt.Sprintf("Get: %s,\n", typeToType[d.Get]))
	} else {
		buf.WriteString("Get: types.NeverType,\n")
	}
	if d.Set != "" {
		buf.WriteString(fmt.Sprintf("Set: %s,\n", typeToType[d.Set]))
	} else {
		buf.WriteString("Set: types.NeverType,\n")
	}
	buf.WriteString(fmt.Sprintf("Unset: %t,\n", d.Unset))
	buf.WriteString(fmt.Sprintf("Scopes: %s,\n", strings.Join(d.On, "|")))
	buf.WriteString(fmt.Sprintf(`Reference: "%s"`+",\n", d.Ref))
	buf.WriteString("},\n")
	return buf.String()
}

type Predefined map[string]*Definition
type Object struct {
	Items map[string]*Object
	Value *Definition
}

type PredefinedGenerator struct {
	buf    bytes.Buffer
	input  string
	output string
}

func newPredefinedGenerator() *PredefinedGenerator {
	return &PredefinedGenerator{
		input:  "./predefined.yml",
		output: "../context/predefined.go",
	}
}

func (g *PredefinedGenerator) generate() error {
	fp, err := os.Open(g.input)
	if err != nil {
		return err
	}
	defer fp.Close()

	defs := Predefined{}
	if err := yaml.NewDecoder(fp).Decode(&defs); err != nil {
		return err
	}

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
			m = g.addOrSet(m, j)
		}
		m.Value = v
	}

	g.buf.WriteString("Variables{\n")
	for _, k := range g.keySort(vars) {
		v := vars[k]
		g.buf.WriteString(quote(k) + ": &Object{\n")
		g.buf.WriteString("Items: map[string]*Object{\n")
		g.generateObject(v)
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

func (g *PredefinedGenerator) writeToFile() error {
	buf := new(bytes.Buffer)
	tpl := template.Must(template.New("predefined").Parse(predefinedVariables))
	if err := tpl.Execute(buf, map[string]interface{}{
		"Variables": g.buf.String(),
	}); err != nil {
		return err
	}

	ret, err := format.Source(buf.Bytes())
	if err != nil {
		fmt.Println(buf.String())
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

func (g *PredefinedGenerator) addOrSet(v *Object, key string) *Object {
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

func (g *PredefinedGenerator) generateObject(value *Object) {
	for _, k := range g.keySort(value.Items) {
		v := value.Items[k]
		g.buf.WriteString(quote(k) + ": &Object{\n")
		g.buf.WriteString("Items: map[string]*Object{\n")
		g.generateObject(v)
		g.buf.WriteString("},\n")
		if v.Value != nil {
			g.buf.WriteString("Value: ")
			g.buf.WriteString(v.Value.String())
		}
		g.buf.WriteString("},\n")
	}
}

func (g *PredefinedGenerator) keySort(m map[string]*Object) []string {
	keys := make([]string, 0, len(m))
	for k, _ := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	return keys
}
