package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type Node interface {
	String() string
	GetMeta() *Meta
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
	Comments CommentsMap
	Leading  Comments
	Trailing Comments
	Infix    Comments
	Nest     int
}

func (m *Meta) LeadingComment() string {
	leading := m.Comments.Get(PlaceLeading)
	if len(leading) == 0 {
		return ""
	}
	var buf bytes.Buffer

	for i := range leading {
		buf.WriteString(indent(m.Nest) + leading[i].String() + "\n")
	}

	return buf.String()
}

func (m *Meta) LeadingInlineComment() string {
	leading := m.Comments.Get(PlaceLeading)
	if len(leading) == 0 {
		return ""
	}
	var buf bytes.Buffer

	for i := range leading {
		buf.WriteString(indent(m.Nest) + leading[i].String() + " ")
	}

	return buf.String()
}

func (m *Meta) TrailingComment() string {
	trailing := m.Comments.Get(PlaceTrailing)
	if len(trailing) == 0 {
		return ""
	}
	var buf bytes.Buffer

	for i := range trailing {
		buf.WriteString(trailing[i].String())
	}

	return " " + buf.String()
}

func (m *Meta) InfixComment() string {
	infix := m.Comments.Get(PlaceInfix)
	if len(infix) == 0 {
		return ""
	}
	var buf bytes.Buffer

	for i := range infix {
		buf.WriteString(indent(m.Nest) + infix[i].String() + "\n")
	}

	return buf.String()
}

func (m *Meta) Comment(placement CommentPlace) string {
	cs := m.Comments.Get(placement)
	if len(cs) == 0 {
		return ""
	}
	var buf bytes.Buffer

	for i := range cs {
		buf.WriteString(cs[i].String())
	}

	return buf.String()
}

func New(t token.Token, nest int, opts ...Option) *Meta {
	m := &Meta{
		Token:    t,
		Nest:     nest,
		Comments: CommentsMap{},
	}

	for i := range opts {
		opts[i](m)
	}

	return m
}

type Option func(m *Meta)

func WithComments(cm CommentsMap) Option {
	return func(m *Meta) {
		m.Comments = cm
	}
}
