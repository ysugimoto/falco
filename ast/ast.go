package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type Node interface {
	String() string
	GetToken() token.Token
}

type Statement interface {
	Node
	statement()
	GetComments() string
}

type Expression interface {
	Node
	expression()
}

// VCL is a root of program
type VCL struct {
	Statements []Statement
}

func (v *VCL) String() string {
	var buf bytes.Buffer

	for i := range v.Statements {
		buf.WriteString(v.Statements[i].String())
	}

	return buf.String()
}

func (v *VCL) GetToken() token.Token {
	return token.Null
}

type Operator struct {
	Token    token.Token
	Operator string
}

func (o *Operator) String() string { return o.Operator }

func indent(lv int) string {
	var str string
	for i := 0; i < lv; i++ {
		str += "  "
	}
	return str
}
