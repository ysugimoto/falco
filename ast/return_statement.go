package ast

import (
	"bytes"
)

type ReturnStatement struct {
	*Meta
	ReturnExpression *Expression
	HasParenthesis   bool
}

func (r *ReturnStatement) statement()     {}
func (r *ReturnStatement) GetMeta() *Meta { return r.Meta }
func (r *ReturnStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(r.LeadingComment())
	if r.ReturnExpression != nil {
		buf.WriteString(indent(r.Nest) + "return(" + (*r.ReturnExpression).String() + ");")
	} else {
		buf.WriteString(indent(r.Nest) + "return;")
	}
	buf.WriteString(r.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
