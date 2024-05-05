package ast

import (
	"bytes"
)

type ImportStatement struct {
	*Meta
	Name *Ident
}

func (i *ImportStatement) Statement()     {}
func (i *ImportStatement) GetMeta() *Meta { return i.Meta }
func (i *ImportStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(i.LeadingComment(lineFeed))
	buf.WriteString(indent(i.Nest) + "import" + paddingLeft(i.Name.String()) + ";")
	buf.WriteString(i.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
