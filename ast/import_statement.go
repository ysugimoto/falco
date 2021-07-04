package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type ImportStatement struct {
	*Meta
	Name *Ident
}

func (i *ImportStatement) statement()            {}
func (i *ImportStatement) GetToken() token.Token { return i.Token }
func (i *ImportStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(i.LeadingComment())
	buf.WriteString(indent(i.Nest) + "import " + i.Name.String() + ";")
	buf.WriteString(i.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
