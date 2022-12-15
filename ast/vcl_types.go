package ast

import (
	"fmt"
)

type Ident struct {
	*Meta
	Value string
}

func (i *Ident) expression()    {}
func (i *Ident) GetMeta() *Meta { return i.Meta }
func (i *Ident) String() string {
	return i.LeadingInlineComment() + i.Value + i.TrailingComment()
}

type IP struct {
	*Meta
	Value string
}

func (i *IP) expression()    {}
func (i *IP) GetMeta() *Meta { return i.Meta }
func (i *IP) String() string {
	return i.LeadingInlineComment() + i.Value + i.TrailingComment()
}

type Boolean struct {
	*Meta
	Value bool
}

func (b *Boolean) expression()    {}
func (b *Boolean) GetMeta() *Meta { return b.Meta }
func (b *Boolean) String() string {
	return b.LeadingInlineComment() + fmt.Sprintf("%t", b.Value) + b.TrailingComment()
}

type Integer struct {
	*Meta
	Value int64
}

func (i *Integer) expression()    {}
func (i *Integer) GetMeta() *Meta { return i.Meta }
func (i *Integer) String() string {
	return i.LeadingInlineComment() + fmt.Sprintf("%d", i.Value) + i.TrailingComment()
}

type String struct {
	*Meta
	Value string
}

func (s *String) expression()    {}
func (s *String) GetMeta() *Meta { return s.Meta }
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

func (f *Float) expression()    {}
func (f *Float) GetMeta() *Meta { return f.Meta }
func (f *Float) String() string {
	return f.LeadingInlineComment() + fmt.Sprintf("%f", f.Value) + f.TrailingComment()
}

type RTime struct {
	*Meta
	Value string
}

func (r *RTime) expression()    {}
func (r *RTime) GetMeta() *Meta { return r.Meta }
func (r *RTime) String() string {
	return r.LeadingInlineComment() + r.Value + r.TrailingComment()
}
