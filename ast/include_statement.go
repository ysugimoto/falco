package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type IncludeStatement struct {
	Token    token.Token
	Module   *String
	Comments Comments
}

func (i *IncludeStatement) statement()            {}
func (i *IncludeStatement) GetComments() string   { return i.Comments.String() }
func (i *IncludeStatement) GetToken() token.Token { return i.Token }
func (i *IncludeStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(i.Comments.String())
	buf.WriteString("include " + i.Module.String() + ";\n")

	return buf.String()
}
