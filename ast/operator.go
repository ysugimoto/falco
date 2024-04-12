package ast

type Operator struct {
	*Meta
	Operator string
}

func (o *Operator) String() string { return o.Operator }
