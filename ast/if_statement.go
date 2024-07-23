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

func (i *IfStatement) ID() uint64     { return i.Meta.ID }
func (i *IfStatement) Statement()     {}
func (i *IfStatement) GetMeta() *Meta { return i.Meta }
func (i *IfStatement) String() string {
	var buf bytes.Buffer
	var tmp Comments

	buf.WriteString(i.LeadingComment(lineFeed))
	buf.WriteString(indent(i.Nest) + i.Keyword)
	buf.WriteString(paddingLeft(i.InfixComment(inline)))
	buf.WriteString(" (")
	buf.WriteString(i.Condition.String())
	buf.WriteString(")")
	buf.WriteString(paddingLeft(i.Consequence.LeadingComment(inline)))
	buf.WriteString(" ")
	tmp = i.Consequence.Leading
	i.Consequence.Leading = Comments{}
	buf.WriteString(i.Consequence.String())
	i.Consequence.Leading = tmp

	for _, a := range i.Another {
		buf.WriteString("\n")
		buf.WriteString(a.LeadingComment(lineFeed))
		buf.WriteString(indent(i.Nest) + "else if")
		buf.WriteString(paddingLeft(a.InfixComment(inline)))
		buf.WriteString(" (")
		buf.WriteString(a.Condition.String())
		buf.WriteString(")")
		buf.WriteString(paddingLeft(a.Consequence.LeadingComment(inline)))
		buf.WriteString(" ")
		a.Consequence.Leading = Comments{}
		buf.WriteString(a.Consequence.String())
		a.Consequence.Leading = tmp
		buf.WriteString(a.TrailingComment(inline))
	}
	if i.Alternative != nil {
		buf.WriteString("\n")
		buf.WriteString(i.Alternative.String())
	}
	buf.WriteString(i.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}

type ElseStatement struct {
	*Meta
	Consequence *BlockStatement
}

func (e *ElseStatement) ID() uint64     { return e.Meta.ID }
func (e *ElseStatement) Statement()     {}
func (e *ElseStatement) GetMeta() *Meta { return e.Meta }
func (e *ElseStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(e.LeadingComment(lineFeed))
	buf.WriteString(indent(e.Nest) + "else")
	buf.WriteString(paddingLeft(e.InfixComment(inline)))
	buf.WriteString(" ")
	buf.WriteString(e.Consequence.String())

	return buf.String()
}
