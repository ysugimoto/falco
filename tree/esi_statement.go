package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type EsiStatement struct {
	*Meta
}

func (e *EsiStatement) statement()            {}
func (e *EsiStatement) GetToken() token.Token { return e.Token }
func (e *EsiStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(e.LeadingComment())
	buf.WriteString(indent(e.Nest) + "esi;")
	buf.WriteString(e.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
