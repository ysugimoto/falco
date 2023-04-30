package resolver

import (
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
)

type StaticResolver struct {
	vcl *VCL
}

func NewStaticResolver(name, content string) *StaticResolver {
	return &StaticResolver{
		vcl: &VCL{
			Name: name,
			Data: content,
		},
	}
}

func (s *StaticResolver) MainVCL() (*VCL, error) {
	return s.vcl, nil
}

func (s *StaticResolver) Resolve(stmt *ast.IncludeStatement) (*VCL, error) {
	return nil, errors.New("Static Resolver returns error")
}

func (s *StaticResolver) Name() string { return "__STATIC__" }
