package parser

import (
	"fmt"
)

// nolint: unused
func (p *Parser) debug(mark string) {
	fmt.Printf(
		"[%s] curToken: %s / peekToken: %s\n",
		mark, p.curToken.Token, p.peekToken.Token,
	)
}
