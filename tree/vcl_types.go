package ast

import (
	"fmt"

	"github.com/ysugimoto/falco/token"
)

type Ident struct {
	*Meta
	Value string
}

func (i *Ident) expression()           {}
func (i *Ident) GetToken() token.Token { return i.Token }
func (i *Ident) String() string {
	return i.LeadingInlineComment() + i.Value + i.TrailingComment()
}

type IP struct {
	*Meta
	Value string
}

func (i *IP) expression()           {}
func (i *IP) GetToken() token.Token { return i.Token }
func (i *IP) String() string {
	return i.LeadingInlineComment() + i.Value + i.TrailingComment()
}

type Boolean struct {
	*Meta
	Value bool
}

func (b *Boolean) expression()           {}
func (b *Boolean) GetToken() token.Token { return b.Token }
func (b *Boolean) String() string {
	return b.LeadingInlineComment() + fmt.Sprintf("%t", b.Value) + b.TrailingComment()
}

type Integer struct {
	*Meta
	Value int64
}

func (i *Integer) expression()           {}
func (i *Integer) GetToken() token.Token { return i.Token }
func (i *Integer) String() string {
	return i.LeadingInlineComment() + fmt.Sprintf("%d", i.Value) + i.TrailingComment()
}

type String struct {
	*Meta
	Value string
}

func (s *String) expression()           {}
func (s *String) GetToken() token.Token { return s.Token }
func (s *String) String() string {
	if s.Token.Offset == 4 { // offset=4 means bracket string
		return s.LeadingComment() + fmt.Sprintf(`{"%s"}`, s.Value) + s.TrailingComment()
	}
	return s.LeadingInlineComment() + fmt.Sprintf(`"%s"`, s.Value) + s.TrailingComment()
}

type Float struct {
	*Meta
	Value float64
}

func (f *Float) expression()           {}
func (f *Float) GetToken() token.Token { return f.Token }
func (f *Float) String() string {
	return f.LeadingInlineComment() + fmt.Sprintf("%f", f.Value) + f.TrailingComment()
}

type RTime struct {
	*Meta
	Value string
}

func (r *RTime) expression()           {}
func (r *RTime) GetToken() token.Token { return r.Token }
func (r *RTime) String() string {
	return r.LeadingInlineComment() + r.Value + r.TrailingComment()
}
