package resolver

import (
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
)

type EmptyResolver struct{}

func (e *EmptyResolver) MainVCL() (*VCL, error) {
	return nil, errors.New("Empty Resolver returns error")
}

func (e *EmptyResolver) Resolve(stmt *ast.IncludeStatement) (*VCL, error) {
	return nil, errors.New("Empty Resolver returns error")
}

func (e *EmptyResolver) Name() string           { return "__EMPTY__" }
func (e *EmptyResolver) IncludePaths() []string { return []string{} }
