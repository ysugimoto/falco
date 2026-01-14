package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

// VCL is a root of program
type VCL struct {
	Statements []Statement
	IsSnippet  bool // True if parsed as a snippet (statements without subroutine wrapper)
}

func (v *VCL) String() string {
	var buf bytes.Buffer

	for i := range v.Statements {
		buf.WriteString(v.Statements[i].String())
	}

	return buf.String()
}

func (v *VCL) GetMeta() *Meta {
	return New(token.Null, 0)
}

func (v *VCL) ID() uint64 {
	return 0
}
