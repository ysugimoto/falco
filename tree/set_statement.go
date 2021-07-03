package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type SetStatement struct {
	*Meta
	Ident    *Ident
	Operator *Operator
	Value    Expression
}

func (s *SetStatement) statement()            {}
func (s *SetStatement) GetToken() token.Token { return s.Token }
func (s *SetStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(s.LeadingComment())
	buf.WriteString(indent(s.Nest) + "set ")
	buf.WriteString(s.Ident.String())
	buf.WriteString(" " + s.Operator.String() + " ")
	buf.WriteString(s.Value.String() + ";")
	buf.WriteString(s.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
