package ast

import (
	"bytes"
)

type SyntheticBase64Statement struct {
	*Meta
	Value Expression
}

func (s *SyntheticBase64Statement) statement()     {}
func (s *SyntheticBase64Statement) GetMeta() *Meta { return s.Meta }
func (s *SyntheticBase64Statement) String() string {
	var buf bytes.Buffer

	buf.WriteString(s.LeadingComment())
	buf.WriteString(indent(s.Nest) + "synthetic.base64 " + s.Value.String() + ";")
	buf.WriteString(s.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
