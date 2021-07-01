package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type SyntheticBase64Statement struct {
	Token     token.Token
	Value     Expression
	NestLevel int
	Comments  Comments
}

func (s *SyntheticBase64Statement) statement()            {}
func (s *SyntheticBase64Statement) GetComments() string   { return s.Comments.String() }
func (s *SyntheticBase64Statement) GetToken() token.Token { return s.Token }
func (s *SyntheticBase64Statement) String() string {
	var buf bytes.Buffer

	buf.WriteString(s.Comments.String())
	buf.WriteString(indent(s.NestLevel) + "synthetic.base64 " + s.Value.String() + ";\n")

	return buf.String()
}
