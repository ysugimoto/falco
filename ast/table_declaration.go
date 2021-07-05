package ast

import (
	"bytes"
)

type TableDeclaration struct {
	*Meta
	Name       *Ident
	ValueType  *Ident
	Properties []*TableProperty
}

func (t *TableDeclaration) statement()     {}
func (t *TableDeclaration) GetMeta() *Meta { return t.Meta }
func (t *TableDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(t.LeadingComment())
	buf.WriteString("table ")
	buf.WriteString(t.Name.String())
	if t.ValueType != nil {
		buf.WriteString(" " + t.ValueType.String())
	}
	buf.WriteString(" {\n")
	for _, props := range t.Properties {
		buf.WriteString(props.String())
	}
	buf.WriteString("}")
	buf.WriteString(t.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}

type TableProperty struct {
	*Meta
	Key      *String
	Value    Expression
	HasComma bool
}

func (t *TableProperty) String() string {
	var buf bytes.Buffer

	buf.WriteString(t.LeadingComment())
	buf.WriteString(indent(t.Nest) + t.Key.String())
	buf.WriteString(": ")
	buf.WriteString(t.Value.String())
	buf.WriteString(",")
	buf.WriteString(t.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
