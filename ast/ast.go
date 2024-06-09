package ast

import (
	"bytes"
	"strings"

	"github.com/ysugimoto/falco/token"
)

type Node interface {
	String() string
	GetMeta() *Meta
}

type Statement interface {
	Node
	Statement()
	LeadingComment(combinationMode) string
	TrailingComment(combinationMode) string
	InfixComment(combinationMode) string
}

type Expression interface {
	Node
	Expression()
	LeadingComment(combinationMode) string
	TrailingComment(combinationMode) string
	InfixComment(combinationMode) string
}

// Meta struct of all nodes
type Meta struct {
	ID                 uint64
	Token              token.Token
	Leading            Comments
	Trailing           Comments
	Infix              Comments
	Nest               int
	PreviousEmptyLines int
}

// combinationMode represents comment combination mode
type combinationMode string

const (
	lineFeed combinationMode = "\n"
	inline   combinationMode = " "
)

func (m *Meta) comment(cs Comments, sep combinationMode) string {
	if len(cs) == 0 {
		return ""
	}
	var buf bytes.Buffer

	for i := range cs {
		buf.WriteString(indent(m.Nest) + cs[i].String() + string(sep))
	}

	return buf.String()
}

func (m *Meta) LeadingComment(cm combinationMode) string {
	return m.comment(m.Leading, cm)
}

func (m *Meta) TrailingComment(cm combinationMode) string {
	return paddingLeft(m.comment(m.Trailing, cm))
}

func (m *Meta) InfixComment(cm combinationMode) string {
	return m.comment(m.Infix, cm)
}

var idCounter uint64

func New(t token.Token, nest int, comments ...Comments) *Meta {
	idCounter++
	m := &Meta{
		ID:       idCounter,
		Token:    t,
		Nest:     nest,
		Leading:  Comments{},
		Trailing: Comments{},
		Infix:    Comments{},
	}

	switch len(comments) {
	case 0:
		break
	case 1:
		m.Leading = comments[0]
	case 2:
		m.Leading = comments[0]
		m.Trailing = comments[1]
	default:
		m.Leading = comments[0]
		m.Trailing = comments[1]
		m.Infix = comments[2]
	}

	return m
}

type Operator struct {
	*Meta
	Operator string
}

func (o *Operator) String() string { return o.Operator }

// Format redundant white space
func padding(s string) string {
	trimmed := strings.Trim(s, " ")
	if trimmed == "" {
		return ""
	}
	return " " + trimmed + " "
}

func paddingLeft(s string) string {
	trimmed := strings.Trim(s, " ")
	if trimmed == "" {
		return ""
	}
	return " " + trimmed
}

func paddingRight(s string) string {
	trimmed := strings.Trim(s, " ")
	if trimmed == "" {
		return ""
	}
	return trimmed + " "
}
