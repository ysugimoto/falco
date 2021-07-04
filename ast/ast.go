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
	LeadingComment() string
	TrailingComment() string
}

type Expression interface {
	Node
	expression()
	LeadingComment() string
	TrailingComment() string
}

// Meta struct of all nodes
type Meta struct {
	Token    token.Token
	Leading  Comments
	Trailing Comments
	Nest     int
}

func (m *Meta) LeadingComment() string {
	if len(m.Leading) == 0 {
		return ""
	}
	var buf bytes.Buffer

	for i := range m.Leading {
		buf.WriteString(indent(m.Nest) + m.Leading[i].String() + "\n")
	}

	return buf.String()
}

func (m *Meta) LeadingInlineComment() string {
	if len(m.Leading) == 0 {
		return ""
	}
	var buf bytes.Buffer

	for i := range m.Leading {
		buf.WriteString(indent(m.Nest) + m.Leading[i].String() + " ")
	}

	return buf.String()
}

func (m *Meta) TrailingComment() string {
	if len(m.Trailing) == 0 {
		return ""
	}
	var buf bytes.Buffer

	for i := range m.Trailing {
		buf.WriteString(m.Trailing[i].String())
	}

	return " " + buf.String()
}

func New(t token.Token, nest int, comments ...Comments) *Meta {
	m := &Meta{
		Token:    t,
		Nest:     nest,
		Leading:  Comments{},
		Trailing: Comments{},
	}

	if len(comments) == 1 {
		m.Leading = comments[0]
	} else if len(comments) > 1 {
		m.Leading = comments[0]
		m.Trailing = comments[1]
	}

	return m
}

type Operator struct {
	Token    token.Token
	Operator string
}

func (o *Operator) String() string { return o.Operator }
