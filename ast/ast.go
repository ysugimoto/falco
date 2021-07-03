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
}

type Expression interface {
	Node
	expression()
}

// Base struct of all nodes
type Base struct {
	Token    token.Token
	Leading  Comments
	Trailing Comments
	Nest     int
}

func (b *Base) LeadingComment() string {
	if len(b.Leading) == 0 {
		return ""
	}
	var buf bytes.Buffer

	for i := range b.Leading {
		buf.WriteString(b.Leading[i].String(b.Nest) + "\n")
	}

	return buf.String()
}

func (b *Base) TrailingComment() string {
	if len(b.Leading) == 0 {
		return ""
	}
	var buf bytes.Buffer

	for i := range b.Trailing {
		buf.WriteString(b.Trailing[i].String(0))
	}

	return " " + buf.String()
}

func New(t token.Token, nest int, comments ...Comments) *Base {
	b := &Base{
		Token:    t,
		Nest:     nest,
		Leading:  Comments{},
		Trailing: Comments{},
	}

	if len(comments) == 1 {
		b.Leading = comments[0]
	} else if len(comments) > 1 {
		b.Leading = comments[0]
		b.Trailing = comments[1]
	}

	return b
}

type LineFeed struct{}

func (l *LineFeed) expression()    {}
func (l *LineFeed) statement()     {}
func (l *LineFeed) String() string { return "\n" }
