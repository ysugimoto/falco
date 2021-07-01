package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type ImportStatement struct {
	Token    token.Token
	Value    *Ident
	Comments Comments
}

func (i *ImportStatement) statement()            {}
func (i *ImportStatement) GetComments() string   { return i.Comments.String() }
func (i *ImportStatement) GetToken() token.Token { return i.Token }
func (i *ImportStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(i.Comments.String())
	buf.WriteString("import " + i.Value.String() + ";\n")

	return buf.String()
}
