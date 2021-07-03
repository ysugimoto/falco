package ast

type Operator struct {
	Token    token.Token
	Operator string
}

func (o *Operator) String() string { return o.Operator }
