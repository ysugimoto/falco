// +build ignore

package parser

import (
	"fmt"

	"github.com/k0kubun/pp"
)

// nolint: unused
func (p *Parser) debug(mark string) {
	fmt.Printf("[%s] curToken: %s / peekToken: %s\n", mark, p.curToken, p.peekToken)
}

// nolint: unused
func (p *Parser) pp(v interface{}) {
	pp.Println(v)
}
