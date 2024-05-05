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

func (t *TableDeclaration) Statement()     {}
func (t *TableDeclaration) GetMeta() *Meta { return t.Meta }
func (t *TableDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(t.LeadingComment(lineFeed))
	buf.WriteString("table")
	buf.WriteString(paddingLeft(t.Name.String()))
	if t.ValueType != nil {
		buf.WriteString(paddingLeft(t.ValueType.String()))
	}
	buf.WriteString(" {\n")
	for _, props := range t.Properties {
		buf.WriteString(props.String())
	}
	buf.WriteString("}")
	buf.WriteString(t.TrailingComment(inline))
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

	buf.WriteString(t.LeadingComment(lineFeed))
	buf.WriteString(indent(t.Nest) + t.Key.String())
	buf.WriteString(":")
	buf.WriteString(paddingLeft(t.Value.String()))
	buf.WriteString(",")
	buf.WriteString(t.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
