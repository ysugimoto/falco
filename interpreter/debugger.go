package interpreter

import (
	"github.com/ysugimoto/falco/ast"
)

type DebugStep int

const (
	DebugStepInit DebugStep = iota
	DebugStepIn
	DebugStepOver
	DebugStepOut
)

type DebugFunc func(step DebugStep, node ast.Node)

func DefaultDebugFunc(step DebugStep, node ast.Node) {
	// Should be empty because do not any debug step as default
}
