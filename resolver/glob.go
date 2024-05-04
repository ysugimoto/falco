package resolver

import (
	"fmt"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
)

// GlobResolver is glob pattern factory resolver, will be used for formatter
// Note that GlobResolver does not want to include paths
// because formatter does not need to resolve included files
type GlobResolver struct {
	main string
}

func NewGlobResolver(patterns ...string) ([]Resolver, error) {
	var resolvers []Resolver

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, errors.New(fmt.Sprintf(`Invalid glob pattern "%s" provided`, pattern))
		}
		for i := range matches {
			abs, err := filepath.Abs(matches[i])
			if err != nil {
				return nil, errors.New(fmt.Sprintf(`Failed to get abosulte path: %s`, err.Error()))
			}
			resolvers = append(resolvers, &GlobResolver{
				main: abs,
			})
		}
	}

	return resolvers, nil
}

func (g *GlobResolver) Name() string {
	return ""
}

func (g *GlobResolver) MainVCL() (*VCL, error) {
	return getVCL(g.main)
}

func (g *GlobResolver) Resolve(sttmt *ast.IncludeStatement) (*VCL, error) {
	return nil, errors.New("GlobResolver does not support resolving VCL")
}
