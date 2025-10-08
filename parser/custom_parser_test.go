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
func (d *DescribeStatement) Lint(nodeLinter func(ast.Node)) error {
	return nil
}

type DescribeParser struct{}

func (d *DescribeParser) Ident() string {
	return "describe"
}
func (d *DescribeParser) Token() token.TokenType {
	return token.Custom("DESCRIBE")
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
		case token.TokenType("BEFORE_EACH"):
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
	stmt.Meta.EndLine = p.curToken.Token.Line
	stmt.Meta.EndPosition = p.curToken.Token.Position

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

func (b *BeforeEachStatement) Lint(nodeLinter func(ast.Node)) error {
	return nil
}

type BeforeEachParser struct{}

func (b *BeforeEachParser) Ident() string {
	return "before_each"
}
func (b *BeforeEachParser) Token() token.TokenType {
	return token.Custom("BEFORE_EACH")
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
	stmt.Meta.EndLine = p.curToken.Token.Line
	stmt.Meta.EndPosition = p.curToken.Token.Position

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
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.Custom("DESCRIBE"),
						Literal:  "describe",
						Line:     2,
						Position: 1,
					},
					Leading:            comments("// Leading comment"),
					Trailing:           comments("// Trailing comment"),
					Infix:              comments(),
					Nest:               0,
					PreviousEmptyLines: 0,
					EndLine:            10,
					EndPosition:        1,
				},
				Name: &ast.Ident{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.IDENT,
							Literal:  "foo",
							Line:     2,
							Position: 10,
						},
						Leading:            comments(),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               0,
						PreviousEmptyLines: 0,
						EndLine:            2,
						EndPosition:        12,
					},
					Value: "foo",
				},
				BeforeEach: &BeforeEachStatement{
					Meta: &ast.Meta{
						Token: token.Token{
							Type:     token.Custom("BEFORE_EACH"),
							Literal:  "before_each",
							Line:     3,
							Position: 2,
						},
						Leading:            comments(),
						Trailing:           comments(),
						Infix:              comments(),
						Nest:               1,
						PreviousEmptyLines: 0,
						EndLine:            5,
						EndPosition:        2,
					},
					Block: &ast.BlockStatement{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.LEFT_BRACE,
								Literal:  "{",
								Line:     3,
								Position: 14,
							},
							Leading:            comments(),
							Trailing:           comments(),
							Infix:              comments(),
							Nest:               2,
							PreviousEmptyLines: 0,
							EndLine:            5,
							EndPosition:        2,
						},
						Statements: []ast.Statement{
							&ast.SetStatement{
								Meta: &ast.Meta{
									Token: token.Token{
										Type:     token.SET,
										Literal:  "set",
										Line:     4,
										Position: 3,
									},
									Leading:            comments(),
									Trailing:           comments(),
									Infix:              comments(),
									Nest:               2,
									PreviousEmptyLines: 0,
									EndLine:            4,
									EndPosition:        26,
								},
								Ident: &ast.Ident{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.IDENT,
											Literal:  "req.http.Foo",
											Line:     4,
											Position: 7,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        18,
									},
									Value: "req.http.Foo",
								},
								Operator: &ast.Operator{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.ASSIGN,
											Literal:  "=",
											Line:     4,
											Position: 20,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        20,
									},
									Operator: "=",
								},
								Value: &ast.String{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.STRING,
											Literal:  "bar",
											Line:     4,
											Position: 22,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            4,
										EndPosition:        26,
									},
									Value: "bar",
								},
							},
						},
					},
				},
				Subroutines: []*ast.SubroutineDeclaration{
					{
						Meta: &ast.Meta{
							Token: token.Token{
								Type:     token.SUBROUTINE,
								Literal:  "sub",
								Line:     7,
								Position: 2,
							},
							Leading:            comments(),
							Trailing:           comments(),
							Infix:              comments(),
							Nest:               1,
							PreviousEmptyLines: 1,
							EndLine:            9,
							EndPosition:        2,
						},
						Name: &ast.Ident{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.IDENT,
									Literal:  "test_foo_recv",
									Line:     7,
									Position: 6,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               1,
								PreviousEmptyLines: 0,
								EndLine:            7,
								EndPosition:        18,
							},
							Value: "test_foo_recv",
						},
						Block: &ast.BlockStatement{
							Meta: &ast.Meta{
								Token: token.Token{
									Type:     token.LEFT_BRACE,
									Literal:  "{",
									Line:     7,
									Position: 20,
								},
								Leading:            comments(),
								Trailing:           comments(),
								Infix:              comments(),
								Nest:               2,
								PreviousEmptyLines: 0,
								EndLine:            9,
								EndPosition:        2,
							},
							Statements: []ast.Statement{
								&ast.SetStatement{
									Meta: &ast.Meta{
										Token: token.Token{
											Type:     token.SET,
											Literal:  "set",
											Line:     8,
											Position: 3,
										},
										Leading:            comments(),
										Trailing:           comments(),
										Infix:              comments(),
										Nest:               2,
										PreviousEmptyLines: 0,
										EndLine:            8,
										EndPosition:        26,
									},
									Ident: &ast.Ident{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.IDENT,
												Literal:  "req.http.Bar",
												Line:     8,
												Position: 7,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            8,
											EndPosition:        18,
										},
										Value: "req.http.Bar",
									},
									Operator: &ast.Operator{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.ASSIGN,
												Literal:  "=",
												Line:     8,
												Position: 20,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            8,
											EndPosition:        20,
										},
										Operator: "=",
									},
									Value: &ast.String{
										Meta: &ast.Meta{
											Token: token.Token{
												Type:     token.STRING,
												Literal:  "baz",
												Line:     8,
												Position: 22,
											},
											Leading:            comments(),
											Trailing:           comments(),
											Infix:              comments(),
											Nest:               2,
											PreviousEmptyLines: 0,
											EndLine:            8,
											EndPosition:        26,
										},
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
