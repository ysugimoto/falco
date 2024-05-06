package ast

import "bytes"

type RatecounterDeclaration struct {
	*Meta
	Name  *Ident
	Block *BlockStatement
}

func (r *RatecounterDeclaration) Statement()     {}
func (r *RatecounterDeclaration) GetMeta() *Meta { return r.Meta }
func (r *RatecounterDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(r.LeadingComment(lineFeed))
	buf.WriteString("ratecounter")
	buf.WriteString(padding(r.Name.String()))
	buf.WriteString(r.Block.String())
	buf.WriteString(r.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
