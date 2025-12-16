package syntax

import (
	"bytes"
	"strings"

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
func (h *HookStatement) Lint(nodeLinter func(node ast.Node)) error {
	return nil
}

type HookParser struct {
	keyword string
}

func (h *HookParser) Ident() string {
	return h.keyword
}
func (h *HookParser) Token() token.TokenType {
	return token.Custom(strings.ToUpper(h.keyword))
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
	stmt.EndLine = p.CurToken().Token.Line
	stmt.EndPosition = p.CurToken().Token.Position

	return stmt, nil
}

var hookParsers = map[token.TokenType]*HookParser{
	token.Custom("BEFORE_RECV"):    {keyword: "before_recv"},
	token.Custom("BEFORE_HASH"):    {keyword: "before_hash"},
	token.Custom("BEFORE_HIT"):     {keyword: "before_hit"},
	token.Custom("BEFORE_MISS"):    {keyword: "before_miss"},
	token.Custom("BEFORE_PASS"):    {keyword: "before_pass"},
	token.Custom("BEFORE_FETCH"):   {keyword: "before_fetch"},
	token.Custom("BEFORE_ERROR"):   {keyword: "before_error"},
	token.Custom("BEFORE_DELIVER"): {keyword: "before_deliver"},
	token.Custom("BEFORE_LOG"):     {keyword: "before_log"},
	token.Custom("AFTER_RECV"):     {keyword: "after_recv"},
	token.Custom("AFTER_HASH"):     {keyword: "after_hash"},
	token.Custom("AFTER_HIT"):      {keyword: "after_hit"},
	token.Custom("AFTER_MISS"):     {keyword: "after_miss"},
	token.Custom("AFTER_PASS"):     {keyword: "after_pass"},
	token.Custom("AFTER_FETCH"):    {keyword: "after_fetch"},
	token.Custom("AFTER_ERROR"):    {keyword: "after_error"},
	token.Custom("AFTER_DELIVER"):  {keyword: "after_deliver"},
	token.Custom("AFTER_LOG"):      {keyword: "after_log"},
}
