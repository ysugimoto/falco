package shared

import (
	"math"
	"sync"

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

type Coverage struct {
	Subroutines *sync.Map // map[string]uint64
	Statements  *sync.Map // map[string]uint64
	Branches    *sync.Map // map[string]uint64
	NodeMap     *sync.Map // map[string]token.Token
}

func NewCoverage() *Coverage {
	return &Coverage{
		Subroutines: &sync.Map{},
		Statements:  &sync.Map{},
		Branches:    &sync.Map{},
		NodeMap:     &sync.Map{},
	}
}

func (c *Coverage) MarkSubroutine(key string) {
	if v, ok := c.Subroutines.Load(key); ok {
		c.Subroutines.Swap(key, v.(uint64)+1) // nolint:errcheck
	}
}

func (c *Coverage) MarkStatement(key string) {
	if v, ok := c.Statements.Load(key); ok {
		c.Statements.Swap(key, v.(uint64)+1) // nolint:errcheck
	}
}

func (c *Coverage) MarkBranch(key string) {
	if v, ok := c.Branches.Load(key); ok {
		c.Branches.Swap(key, v.(uint64)+1) // nolint:errcheck
	}
}

func (c *Coverage) SetupSubroutine(key string, node ast.Node) {
	c.Subroutines.LoadOrStore(key, uint64(0))
	c.NodeMap.LoadOrStore(key, node.GetMeta().Token)
}

func (c *Coverage) SetupStatement(key string, node ast.Node) {
	c.Statements.LoadOrStore(key, uint64(0))
	c.NodeMap.LoadOrStore(key, node.GetMeta().Token)
}

func (c *Coverage) SetupBranch(key string, node ast.Node) {
	c.Branches.LoadOrStore(key, uint64(0))
	c.NodeMap.LoadOrStore(key, node.GetMeta().Token)
}

func (c *Coverage) Factory() *CoverageFactory {
	r := &CoverageFactory{
		Subroutines: make(CoverageFactoryItem),
		Statements:  make(CoverageFactoryItem),
		Branches:    make(CoverageFactoryItem),
		NodeMap:     make(map[string]token.Token),
	}

	c.Subroutines.Range(func(key, val any) bool {
		r.Subroutines[key.(string)] = val.(uint64) // nolint:errcheck
		return true
	})
	c.Statements.Range(func(key, val any) bool {
		r.Statements[key.(string)] = val.(uint64) // nolint:errcheck
		return true
	})
	c.Branches.Range(func(key, val any) bool {
		r.Branches[key.(string)] = val.(uint64) // nolint:errcheck
		return true
	})
	c.NodeMap.Range(func(key, val any) bool {
		r.NodeMap[key.(string)] = val.(token.Token) // nolint:errcheck
		return true
	})

	return r
}

type CoverageFactoryItem map[string]uint64

type CoverageFactory struct {
	Subroutines CoverageFactoryItem
	Statements  CoverageFactoryItem
	Branches    CoverageFactoryItem
	NodeMap     map[string]token.Token
}

func (c *CoverageFactory) Report() *CoverageReport {
	return &CoverageReport{
		Subroutines: c.calculate(c.Subroutines),
		Statements:  c.calculate(c.Statements),
		Branches:    c.calculate(c.Branches),
		NodeMap:     c.NodeMap,
	}
}

func (c *CoverageFactory) calculate(v CoverageFactoryItem) *CoverageReportItem {
	var executed, total uint64
	var percent float64

	for _, val := range v {
		total++
		if val > 0 {
			executed++
		}
	}
	if total > 0 {
		percent = math.Round(float64(executed)/float64(total)*10000) / 100
	}

	return &CoverageReportItem{
		Executed: executed,
		Total:    total,
		Percent:  percent,
	}
}

type CoverageReportItem struct {
	Executed uint64
	Total    uint64
	Percent  float64
}

type CoverageReport struct {
	Subroutines *CoverageReportItem
	Statements  *CoverageReportItem
	Branches    *CoverageReportItem
	NodeMap     map[string]token.Token
}
