package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type IncludeStatement struct {
	*Meta
	Module *String
}

func (i *IncludeStatement) statement()            {}
func (i *IncludeStatement) GetToken() token.Token { return i.Token }
func (i *IncludeStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(i.LeadingComment())
	buf.WriteString(indent(i.Nest) + "include " + i.Module.String() + ";")
	buf.WriteString(i.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
