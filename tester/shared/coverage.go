package shared

import "github.com/ysugimoto/falco/ast"

type Coverage struct {
	Subroutines map[string]bool
	Statements  map[string]bool
	Branches    map[string]bool
	NodeMap     map[string]ast.Node
}

func NewCoverage() *Coverage {
	return &Coverage{
		Subroutines: make(map[string]bool),
		Statements:  make(map[string]bool),
		Branches:    make(map[string]bool),
		NodeMap:     make(map[string]ast.Node),
	}
}

func (c *Coverage) MarkSubroutine(key string) {
	c.Subroutines[key] = true
}

func (c *Coverage) MarkStatement(key string) {
	c.Statements[key] = true
}

func (c *Coverage) MarkBranch(key string) {
	c.Branches[key] = true
}
