package parser

type ParserOption func(p *Parser)

func WithCustomParser(cps ...CustomParser) ParserOption {
	return func(p *Parser) {
		for i := range cps {
			p.customParsers[cps[i].Token()] = cps[i]
		}
	}
}
