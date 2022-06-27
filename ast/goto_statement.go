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

	buf.WriteString(g.LeadingComment())
	buf.WriteString(indent(g.Nest) + "goto " + g.Destination.String() + ";")
	buf.WriteString(g.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
