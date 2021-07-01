package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type FunctionCallExpression struct {
	Token     token.Token
	Function  Expression
	Arguments []Expression
}

func (f *FunctionCallExpression) expression()           {}
func (f *FunctionCallExpression) GetToken() token.Token { return f.Token }
func (f *FunctionCallExpression) String() string {
	var buf bytes.Buffer

	buf.WriteString(f.Function.String() + "(")
	for i, a := range f.Arguments {
		buf.WriteString(a.String())
		if i != len(f.Arguments)-1 {
			buf.WriteString(", ")
		}
	}
	buf.WriteString(")")

	return buf.String()
}
