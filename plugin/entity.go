package plugin

import (
	"github.com/ysugimoto/falco/ast"
)

type VCL struct {
	File string
	AST  *ast.VCL
}

type FalcoTransformInput []*VCL
