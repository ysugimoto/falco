package main

import (
	"bytes"
	"fmt"
	"strings"
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
		buf.WriteString("Extra: func(c *Context, name string) any { return c.Tables[name] },\n")
	}
	buf.WriteString(fmt.Sprintf("Scopes: %s,\n", strings.Join(f.On, "|")))
	buf.WriteString(fmt.Sprintf(`Reference: "%s"`+",\n", f.Ref))
	buf.WriteString("},\n")
	return buf.String()
}

type Spec struct {
	Items map[string]*Spec
	Value *FunctionSpec
}

type Definition struct {
	Get        string   `yaml:"get"`
	Set        string   `yaml:"set"`
	Unset      bool     `yaml:"unset"`
	On         []string `yaml:"on"`
	Ref        string   `yaml:"reference"`
	Deprecated bool     `yaml:"deprecated"`
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
	if d.Deprecated {
		buf.WriteString("Deprecated: true,\n")
	}
	buf.WriteString("},\n")
	return buf.String()
}

type Object struct {
	Items map[string]*Object
	Value *Definition
}
