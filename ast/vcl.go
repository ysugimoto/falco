package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/v2/token"
)

// VCL is a root of program
type VCL struct {
	Statements []Statement
	IsSnippet  bool // True if parsed as a snippet (statements without subroutine wrapper)

	// Comments at the end of the file, after the last statement. They have no
	// statement to be the leading comments of, so they are kept here.
	Trailing Comments
}

func (v *VCL) String() string {
	var buf bytes.Buffer

	for i := range v.Statements {
		buf.WriteString(v.Statements[i].String())
	}
	for i := range v.Trailing {
		buf.WriteString(v.Trailing[i].String() + "\n")
	}

	return buf.String()
}

func (v *VCL) GetMeta() *Meta {
	return New(token.Null, 0)
}

func (v *VCL) ID() uint64 {
	return 0
}
