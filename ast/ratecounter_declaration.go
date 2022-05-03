package ast

import "bytes"

type RatecounterDeclaration struct {
	*Meta
	Name  *Ident
	Block *BlockStatement
}

func (r *RatecounterDeclaration) statement()     {}
func (r *RatecounterDeclaration) GetMeta() *Meta { return r.Meta }
func (r *RatecounterDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(r.LeadingComment())
	buf.WriteString("ratecounter ")
	buf.WriteString(r.Name.String())
	buf.WriteString(" " + r.Block.String())
	buf.WriteString(r.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
