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

	buf.WriteString(s.LeadingComment())
	if s.Test != nil {
		buf.WriteString("case ")
		if s.Test.Operator == "~" {
			buf.WriteString("~")
		}
		buf.WriteString(s.Test.Right.String())
		buf.WriteString(":")
	} else {
		buf.WriteString("default:")
	}
	buf.WriteString(s.TrailingComment())
	buf.WriteString("\n")
	for _, stmt := range s.Statements {
		buf.WriteString(indent(s.Nest) + stmt.String())
	}

	return buf.String()
}
