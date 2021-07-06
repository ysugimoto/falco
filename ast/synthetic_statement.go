package ast

import (
	"bytes"
)

type SyntheticStatement struct {
	*Meta
	Value Expression
}

func (s *SyntheticStatement) statement()     {}
func (s *SyntheticStatement) GetMeta() *Meta { return s.Meta }
func (s *SyntheticStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(s.LeadingComment())
	buf.WriteString(indent(s.Nest) + "synthetic " + s.Value.String() + ";")
	buf.WriteString(s.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
