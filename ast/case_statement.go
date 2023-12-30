package ast

import (
	"bytes"
)

type CaseStatement struct {
	*Meta
	Test       *InfixExpression
	Statements []Statement
}

func (s *CaseStatement) statement()     {}
func (s *CaseStatement) GetMeta() *Meta { return s.Meta }
func (s *CaseStatement) FinalStatement() Statement {
	return s.Statements[len(s.Statements)-1]
}
func (s *CaseStatement) IsBreak() bool {
	_, ok := s.FinalStatement().(*BreakStatement)
	return ok
}
func (s *CaseStatement) IsFallthrough() bool {
	_, ok := s.FinalStatement().(*FallthroughStatement)
	return ok
}
func (s *CaseStatement) TestEqual(other *CaseStatement) bool {
	if s.Test == nil || other.Test == nil || s.Test.Operator != other.Test.Operator {
		return false
	}
	return s.Test.Right.String() == other.Test.Right.String()
}
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
