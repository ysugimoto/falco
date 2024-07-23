package parser

import (
	"bytes"
	"testing"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/token"
)

type DescribeStatement struct {
	*ast.Meta
	Name        *ast.Ident
	BeforeEach  ast.CustomStatement
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
	if d.BeforeEach != nil {
		buf.WriteString(d.BeforeEach.String())
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

type DescribeParser struct{}

func (d *DescribeParser) Literal() string {
	return "describe"
}
func (d *DescribeParser) Parse(p *Parser) (ast.CustomStatement, error) {
	stmt := &DescribeStatement{
		Meta: p.curToken,
	}
	if !p.ExpectPeek(token.IDENT) {
		return nil, UnexpectedToken(p.PeekToken(), token.IDENT)
	}
	stmt.Name = p.ParseIdent()
	if !p.ExpectPeek(token.LEFT_BRACE) {
		return nil, UnexpectedToken(p.PeekToken(), token.LEFT_BRACE)
	}
	SwapLeadingTrailing(p.curToken, stmt.Name.Meta)
	p.NextToken()

	for !p.PeekTokenIs(token.RIGHT_BRACE) {
		tok := p.CurToken()
		switch tok.Token.Type {
		case token.SUBROUTINE:
			sub, err := p.ParseSubroutineDeclaration()
			if err != nil {
				return nil, errors.WithStack(err)
			}
			stmt.Subroutines = append(stmt.Subroutines, sub)
		case token.CUSTOM:
			cs, err := p.ParseCustomToken()
			if err != nil {
				return nil, errors.WithStack(err)
			}
			if cs.Literal() == "before_each" {
				stmt.BeforeEach = cs
			}
		default:
			return nil, UnexpectedToken(p.CurToken())
		}
	}

	p.NextToken() // point to RIGHT_BRACE
	SwapLeadingInfix(p.curToken, stmt.Meta)
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

type BeforeEachStatement struct {
	*ast.Meta
	Block *ast.BlockStatement
}

func (b *BeforeEachStatement) ID() uint64 { return b.Meta.ID }
func (b *BeforeEachStatement) Statement() {}
func (b *BeforeEachStatement) Literal() string {
	return "before_each"
}
func (b *BeforeEachStatement) GetMeta() *ast.Meta {
	return b.Meta
}

func (b *BeforeEachStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(b.LeadingComment("\n"))
	buf.WriteString("before_each ")
	if v := b.InfixComment(" "); v != "" {
		buf.WriteString(v + " ")
	}
	buf.WriteString(b.Block.String())
	buf.WriteString(b.TrailingComment(" "))

	return buf.String()
}

type BeforeEachParser struct{}

func (b *BeforeEachParser) Literal() string {
	return "before_each"
}
func (b *BeforeEachParser) Parse(p *Parser) (ast.CustomStatement, error) {
	stmt := &BeforeEachStatement{
		Meta: p.curToken,
	}
	if !p.ExpectPeek(token.LEFT_BRACE) {
		return nil, UnexpectedToken(p.PeekToken(), token.LEFT_BRACE)
	}
	SwapLeadingInfix(p.curToken, stmt.Meta)
	var err error
	if stmt.Block, err = p.ParseBlockStatement(); err != nil {
		return nil, errors.WithStack(err)
	}

	// point to next declaretion/statement start
	p.NextToken()
	return stmt, nil
}

func TestParseCustomToken(t *testing.T) {
	input := `// Leading comment
describe foo {
  before_each {
	set req.http.Foo = "bar";
  }

  sub test_foo_recv {
	set req.http.Bar = "baz";
  }
} // Trailing comment`
	expect := &ast.VCL{
		Statements: []ast.Statement{
			&DescribeStatement{
				Meta: ast.New(T, 0, comments("// Leading comment"), comments("// Trailing comment")),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "foo",
				},
				BeforeEach: &BeforeEachStatement{
					Meta: ast.New(T, 1),
					Block: &ast.BlockStatement{
						Meta: ast.New(T, 2),
						Statements: []ast.Statement{
							&ast.SetStatement{
								Meta: ast.New(T, 2),
								Ident: &ast.Ident{
									Meta:  ast.New(T, 2),
									Value: "req.http.Foo",
								},
								Operator: &ast.Operator{
									Meta:     ast.New(T, 2),
									Operator: "=",
								},
								Value: &ast.String{
									Meta:  ast.New(T, 2),
									Value: "bar",
								},
							},
						},
					},
				},
				Subroutines: []*ast.SubroutineDeclaration{
					&ast.SubroutineDeclaration{
						Meta: &ast.Meta{
							Token:              T,
							Nest:               1,
							PreviousEmptyLines: 1,
							Leading:            ast.Comments{},
							Infix:              ast.Comments{},
							Trailing:           ast.Comments{},
						},
						Name: &ast.Ident{
							Meta:  ast.New(T, 1),
							Value: "test_foo_recv",
						},
						Block: &ast.BlockStatement{
							Meta: ast.New(T, 2),
							Statements: []ast.Statement{
								&ast.SetStatement{
									Meta: ast.New(T, 2),
									Ident: &ast.Ident{
										Meta:  ast.New(T, 2),
										Value: "req.http.Bar",
									},
									Operator: &ast.Operator{
										Meta:     ast.New(T, 2),
										Operator: "=",
									},
									Value: &ast.String{
										Meta:  ast.New(T, 2),
										Value: "baz",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	cps := []CustomParser{
		&DescribeParser{},
		&BeforeEachParser{},
	}
	vcl, err := New(lexer.NewFromString(input), WithCustomParser(cps...)).ParseVCL()
	if err != nil {
		t.Errorf("%+v", err)
	}
	assert(t, vcl, expect)
}
