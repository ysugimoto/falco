package ast

import (
	"bytes"
)

type IfStatement struct {
	*Meta
	Keyword     string
	Condition   Expression
	Consequence *BlockStatement
	Another     []*IfStatement
	Alternative *ElseStatement
}

func (i *IfStatement) statement()     {}
func (i *IfStatement) GetMeta() *Meta { return i.Meta }
func (i *IfStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(i.LeadingComment())
	buf.WriteString(indent(i.Nest) + i.Keyword + " (")
	buf.WriteString(i.Condition.String())
	buf.WriteString(") ")
	buf.WriteString(i.Consequence.String())

	for _, a := range i.Another {
		buf.WriteString("\n")
		buf.WriteString(a.LeadingComment())
		buf.WriteString(indent(i.Nest) + "else if (")
		buf.WriteString(a.Condition.String())
		buf.WriteString(") ")
		buf.WriteString(a.Consequence.String())
		buf.WriteString(a.TrailingComment())
	}
	if i.Alternative != nil {
		buf.WriteString("\n")
		buf.WriteString(i.Alternative.String())
	}
	buf.WriteString(i.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}

type ElseStatement struct {
	*Meta
	Consequence *BlockStatement
}

func (e *ElseStatement) statement()     {}
func (e *ElseStatement) GetMeta() *Meta { return e.Meta }
func (e *ElseStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(e.LeadingComment())
	buf.WriteString(indent(e.Nest) + "else ")
	buf.WriteString(e.Consequence.String())

	return buf.String()
}
