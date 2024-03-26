package ast

import (
	"bytes"
)

type IfStatement struct {
	*Meta
	Keyword             string
	Condition           Expression
	Consequence         *BlockStatement
	Another             []*IfStatement
	Alternative         *BlockStatement
	AlternativeComments Comments
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
		buf.WriteString(indent(i.Nest) + a.Keyword + " (")
		buf.WriteString(a.Condition.String())
		buf.WriteString(") ")
		buf.WriteString(a.Consequence.String())
		buf.WriteString(a.TrailingComment())
	}
	if i.Alternative != nil {
		buf.WriteString("\n")
		buf.WriteString(i.alternativeComments())
		buf.WriteString(indent(i.Nest) + "else ")
		buf.WriteString(i.Alternative.String())
	}
	buf.WriteString(i.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}

func (i *IfStatement) alternativeComments() string {
	if len(i.AlternativeComments) == 0 {
		return ""
	}
	var buf bytes.Buffer

	for _, v := range i.AlternativeComments {
		buf.WriteString(indent(i.Nest) + v.String() + "\n")
	}

	return buf.String()
}
