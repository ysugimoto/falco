package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type IfStatement struct {
	Token               token.Token
	Condition           Expression
	Consequence         *BlockStatement
	Another             []*IfStatement
	Alternative         *BlockStatement
	NestLevel           int
	Comments            Comments
	AlternativeComments Comments
}

func (i *IfStatement) statement() {}
func (i *IfStatement) GetComments() string {
	var buf bytes.Buffer

	buf.WriteString(i.Comments.String())
	for _, a := range i.Another {
		buf.WriteString(a.Comments.String())
	}
	buf.WriteString(i.AlternativeComments.String())
	return buf.String()
}
func (i *IfStatement) GetToken() token.Token { return i.Token }
func (i *IfStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(i.Comments.String())
	buf.WriteString(indent(i.NestLevel) + "if (")
	buf.WriteString(i.Condition.String())
	buf.WriteString(") ")
	buf.WriteString(i.Consequence.String())
	buf.WriteString("\n")

	for _, a := range i.Another {
		buf.WriteString(a.Comments.String())
		buf.WriteString(indent(i.NestLevel) + "else if (")
		buf.WriteString(a.Condition.String())
		buf.WriteString(") ")
		buf.WriteString(a.Consequence.String())
		buf.WriteString("\n")
	}
	if i.Alternative != nil {
		buf.WriteString(i.AlternativeComments.String())
		buf.WriteString(indent(i.NestLevel) + "else ")
		buf.WriteString(i.Alternative.String())
		buf.WriteString("\n")
	}

	return buf.String()
}
