package resolver

import (
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
)

var (
	ErrEmptyMain = errors.New("Input file is empty")
)

type VCL struct {
	Name string
	Data string
}

// Resolver is an interface to fetch VCL source and dependencies
// from various sources e.g. file or JSON (terraform planned data)
type Resolver interface {
	MainVCL() (*VCL, error)
	Resolve(stmt *ast.IncludeStatement) (*VCL, error)
	Name() string
	// TODO: implement
	// ResolveScopeSnippet(scope string) (*VCL, error)
}
