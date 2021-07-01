package ast

import (
	"fmt"
	"time"

	"github.com/ysugimoto/falco/token"
)

type Ident struct {
	Token token.Token
	Value string
}

func (i *Ident) expression()           {}
func (i *Ident) GetToken() token.Token { return i.Token }
func (i *Ident) String() string {
	return i.Value
}

type IP struct {
	Token token.Token
	Value string
}

func (i *IP) expression()           {}
func (i *IP) GetToken() token.Token { return i.Token }
func (i *IP) String() string {
	return i.Value
}

type Boolean struct {
	Token token.Token
	Value bool
}

func (b *Boolean) expression()           {}
func (b *Boolean) GetToken() token.Token { return b.Token }
func (b *Boolean) String() string {
	return fmt.Sprintf("%t", b.Value)
}

type Integer struct {
	Token token.Token
	Value int64
}

func (i *Integer) expression()           {}
func (i *Integer) GetToken() token.Token { return i.Token }
func (i *Integer) String() string {
	return fmt.Sprintf("%d", i.Value)
}

type String struct {
	Token token.Token
	Value string
}

func (s *String) expression()           {}
func (s *String) GetToken() token.Token { return s.Token }
func (s *String) String() string {
	return fmt.Sprintf(`"%s"`, s.Value)
}

type Float struct {
	Token token.Token
	Value float64
}

func (f *Float) expression()           {}
func (f *Float) GetToken() token.Token { return f.Token }
func (f *Float) String() string {
	return fmt.Sprintf("%f", f.Value)
}

type RTime struct {
	Token    token.Token
	Value    string
	Duration time.Duration
}

func (r *RTime) expression()           {}
func (r *RTime) GetToken() token.Token { return r.Token }
func (r *RTime) String() string {
	return r.Value
}
