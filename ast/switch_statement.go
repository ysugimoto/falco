package ast

import "bytes"

type SwitchStatement struct {
	*Meta
	Control *SwitchControl
	Cases   []*CaseStatement
	Default int
}

func (s *SwitchStatement) statement()     {}
func (s *SwitchStatement) GetMeta() *Meta { return s.Meta }
func (s *SwitchStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(s.LeadingComment())
	buf.WriteString("switch ")
	buf.WriteString(s.Control.String())
	buf.WriteString(" {\n")
	for _, stmt := range s.Cases {
		buf.WriteString(stmt.String())
	}

	buf.WriteString("}")
	buf.WriteString(s.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}

type SwitchControl struct {
	*Meta
	Expression Expression
}

func (s *SwitchControl) statement()     {}
func (s *SwitchControl) GetMeta() *Meta { return s.Meta }
func (s *SwitchControl) String() string {
	var buf bytes.Buffer

	buf.WriteString(s.LeadingComment())
	buf.WriteString("(")
	buf.WriteString(s.Expression.String())
	buf.WriteString(")")

	return buf.String()
}
