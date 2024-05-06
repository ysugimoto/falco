package ast

import (
	"bytes"
)

type SyntheticBase64Statement struct {
	*Meta
	Value Expression
}

func (s *SyntheticBase64Statement) Statement()     {}
func (s *SyntheticBase64Statement) GetMeta() *Meta { return s.Meta }
func (s *SyntheticBase64Statement) String() string {
	var buf bytes.Buffer

	buf.WriteString(s.LeadingComment(lineFeed))
	buf.WriteString(indent(s.Nest) + "synthetic.base64")
	buf.WriteString(paddingLeft(s.Value.String()))
	buf.WriteString(";")
	buf.WriteString(s.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
