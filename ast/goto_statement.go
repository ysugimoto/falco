package ast

import (
	"bytes"
)

type GotoStatement struct {
	*Meta
	Destination *Ident
}

func (g *GotoStatement) statement()     {}
func (g *GotoStatement) GetMeta() *Meta { return g.Meta }
func (g *GotoStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(g.LeadingComment(lineFeed))
	buf.WriteString(indent(g.Nest) + "goto")
	buf.WriteString(paddingLeft(g.Destination.String()))
	buf.WriteString(";")
	buf.WriteString(g.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
