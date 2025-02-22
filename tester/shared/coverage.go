package shared

import (
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/token"
)

type CoverageType int8

const (
	CoverageTypeSubroutine CoverageType = iota
	CoverageTypeStatement
	CoverageTypeBranch
)

func (t CoverageType) String() string {
	switch t {
	case CoverageTypeSubroutine:
		return "subroutine"
	case CoverageTypeStatement:
		return "statement"
	case CoverageTypeBranch:
		return "branch"
	default:
		return ""
	}
}

type CoverageMap map[string]uint64

type Coverage struct {
	Subroutines CoverageMap
	Statements  CoverageMap
	Branches    CoverageMap
	NodeMap     map[string]token.Token
}

func NewCoverage() *Coverage {
	return &Coverage{
		Subroutines: make(CoverageMap),
		Statements:  make(CoverageMap),
		Branches:    make(CoverageMap),
		NodeMap:     make(map[string]token.Token),
	}
}

func (c *Coverage) MarkSubroutine(key string) {
	c.Subroutines[key]++
}

func (c *Coverage) MarkStatement(key string) {
	c.Statements[key]++
}

func (c *Coverage) MarkBranch(key string) {
	c.Branches[key]++
}

func (c *Coverage) SetupSubroutine(key string, node ast.Node) {
	c.Subroutines[key] = 0
	c.NodeMap[key] = node.GetMeta().Token
}

func (c *Coverage) SetupStatement(key string, node ast.Node) {
	c.Statements[key] = 0
	c.NodeMap[key] = node.GetMeta().Token
}

func (c *Coverage) SetupBranch(key string, node ast.Node) {
	c.Branches[key] = 0
	c.NodeMap[key] = node.GetMeta().Token
}
