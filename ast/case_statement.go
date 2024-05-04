package ast

import (
	"bytes"
)

type CaseStatement struct {
	*Meta
	Test        *InfixExpression
	Statements  []Statement
	Fallthrough bool
}

func (s *CaseStatement) statement()     {}
func (s *CaseStatement) GetMeta() *Meta { return s.Meta }
func (s *CaseStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(s.LeadingComment(lineFeed))
	if s.Test != nil {
		buf.WriteString("case")
		buf.WriteString(paddingLeft(s.InfixComment(inline)))
		buf.WriteString(" ")
		if s.Test.Operator == "~" {
			buf.WriteString("~")
		}
		buf.WriteString(s.Test.Right.String())
		buf.WriteString(":")
	} else {
		buf.WriteString("default:")
	}
	buf.WriteString(s.TrailingComment(inline))
	buf.WriteString("\n")
	for _, stmt := range s.Statements {
		buf.WriteString(indent(s.Nest) + stmt.String())
	}

	return buf.String()
}
