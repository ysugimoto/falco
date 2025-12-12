package syntax

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/token"
)

// Declare DescribeStatement
type DescribeStatement struct {
	*ast.Meta
	Name        *ast.Ident
	Befores     map[string]*HookStatement
	Afters      map[string]*HookStatement
	Subroutines []*ast.SubroutineDeclaration
}

func (d *DescribeStatement) ID() uint64 { return d.Meta.ID }
func (d *DescribeStatement) Statement() {}
func (d *DescribeStatement) Literal() string {
	return "describe"
}
func (d *DescribeStatement) GetMeta() *ast.Meta {
	return d.Meta
}
func (d *DescribeStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(d.LeadingComment("\n"))
	buf.WriteString("describe ")
	buf.WriteString(d.Name.String())
	buf.WriteString(" {\n")
	for i := range d.Befores {
		buf.WriteString(d.Befores[i].String())
		buf.WriteString("\n")
	}
	for i := range d.Afters {
		buf.WriteString(d.Afters[i].String())
		buf.WriteString("\n")
	}

	for _, sub := range d.Subroutines {
		buf.WriteString(sub.String())
	}
	buf.WriteString(d.InfixComment("\n"))
	buf.WriteString("}")
	buf.WriteString(d.TrailingComment(" "))

	return buf.String()
}
func (d *DescribeStatement) Lint(nodeLinter func(node ast.Node)) error {
	return nil
}

// Custome parser implementation for "describe" keyword
type DescribeParser struct{}

func (d *DescribeParser) Ident() string {
	return "describe"
}
func (d *DescribeParser) Token() token.TokenType {
	return token.Custom("DESCRIBE")
}
func (d *DescribeParser) Parse(p *parser.Parser) (ast.CustomStatement, error) {
	stmt := &DescribeStatement{
		Meta:    p.CurToken(),
		Befores: make(map[string]*HookStatement),
		Afters:  make(map[string]*HookStatement),
	}
	if !p.ExpectPeek(token.IDENT) {
		return nil, parser.UnexpectedToken(p.PeekToken(), token.IDENT)
	}
	stmt.Name = p.ParseIdent()
	if !p.ExpectPeek(token.LEFT_BRACE) {
		return nil, parser.UnexpectedToken(p.PeekToken(), token.LEFT_BRACE)
	}
	parser.SwapLeadingTrailing(p.CurToken(), stmt.Name.Meta)
	p.NextToken()

	for !p.CurTokenIs(token.RIGHT_BRACE) {
		tok := p.CurToken()
		switch tok.Token.Type {
		case token.SUBROUTINE:
			sub, err := p.ParseSubroutineDeclaration()
			if err != nil {
				return nil, errors.WithStack(err)
			}
			stmt.Subroutines = append(stmt.Subroutines, sub)
			p.NextToken()
		default:
			if hookParser, ok := hookParsers[tok.Token.Type]; ok {
				hook, err := hookParser.Parse(p)
				if err != nil {
					return nil, errors.WithStack(err)
				}
				if t, ok := hook.(*HookStatement); ok {
					switch {
					case strings.HasPrefix(t.keyword, "before"):
						if _, ok := stmt.Befores[t.keyword]; ok {
							return nil, &parser.ParseError{
								Token:   t.GetMeta().Token,
								Message: fmt.Sprintf("%s hook is duplicated", hook.Literal()),
							}
						}
						stmt.Befores[t.keyword] = t
					case strings.HasPrefix(t.keyword, "after"):
						if _, ok := stmt.Afters[t.keyword]; ok {
							return nil, &parser.ParseError{
								Token:   t.GetMeta().Token,
								Message: fmt.Sprintf("%s hook is duplicated", hook.Literal()),
							}
						}
						stmt.Afters[t.keyword] = t
					}
					p.NextToken()
					continue
				}
				return nil, &parser.ParseError{
					Token:   p.CurToken().Token,
					Message: fmt.Sprintf("%s statement could not be placed inside describe", hook.Literal()),
				}
			}
			return nil, parser.UnexpectedToken(p.CurToken())
		}
	}

	parser.SwapLeadingInfix(p.CurToken(), stmt.Meta)
	stmt.Trailing = p.Trailing()
	stmt.EndLine = p.CurToken().Token.Line
	stmt.EndPosition = p.CurToken().Token.Position

	return stmt, nil
}
