package ast

import (
	"bytes"
)

type ReturnStatement struct {
	*Meta
	ReturnExpression            Expression
	HasParenthesis              bool
	ParenthesisLeadingComments  Comments
	ParenthesisTrailingComments Comments
}

func (r *ReturnStatement) Statement()     {}
func (r *ReturnStatement) GetMeta() *Meta { return r.Meta }
func (r *ReturnStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(r.LeadingComment(lineFeed))
	if r.ReturnExpression != nil {
		if r.HasParenthesis {
			buf.WriteString(indent(r.Nest) + "return ")
			if v := r.ParenthesisLeadingComments.String(); v != "" {
				buf.WriteString(v + " ")
			}
			buf.WriteString("(" + r.ReturnExpression.String() + ")")
			if v := r.ParenthesisTrailingComments.String(); v != "" {
				buf.WriteString(" " + v)
			}
			buf.WriteString(";")
		} else {
			buf.WriteString(indent(r.Nest) + "return " + r.ReturnExpression.String() + ";")
		}
	} else {
		buf.WriteString(indent(r.Nest) + "return")
		if v := r.InfixComment(inline); v != "" {
			buf.WriteString(paddingLeft(v))
		}
		buf.WriteString(";")
	}
	buf.WriteString(r.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
