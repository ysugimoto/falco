package syntax

import (
	"bytes"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/token"
)

type HookStatement struct {
	*ast.Meta
	Block   *ast.BlockStatement
	keyword string
}

func (s *HookStatement) ID() uint64 { return s.Meta.ID }
func (s *HookStatement) Statement() {}
func (s *HookStatement) Literal() string {
	return s.keyword
}
func (s *HookStatement) GetMeta() *ast.Meta {
	return s.Meta
}

func (s *HookStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(s.LeadingComment("\n"))
	buf.WriteString(s.keyword + " ")
	if v := s.InfixComment(" "); v != "" {
		buf.WriteString(v + " ")
	}
	buf.WriteString(s.Block.String())
	buf.WriteString(s.TrailingComment(" "))

	return buf.String()
}

type HookParser struct {
	keyword string
}

func (h *HookParser) Literal() string {
	return h.keyword
}
func (h *HookParser) Parse(p *parser.Parser) (ast.CustomStatement, error) {
	stmt := &HookStatement{
		Meta:    p.CurToken(),
		keyword: h.keyword,
	}
	if !p.ExpectPeek(token.LEFT_BRACE) {
		return nil, parser.UnexpectedToken(p.PeekToken(), token.LEFT_BRACE)
	}
	parser.SwapLeadingInfix(p.CurToken(), stmt.Meta)
	var err error
	if stmt.Block, err = p.ParseBlockStatement(); err != nil {
		return nil, errors.WithStack(err)
	}

	return stmt, nil
}
