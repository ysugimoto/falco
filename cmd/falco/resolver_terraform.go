package main

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/terraform"
)

// TerraformResolver is in memory resolver, read and factory vcl data from terraform planned JSON input
type TerraformResolver struct {
	Modules     []*VCL
	Main        *VCL
	ServiceName string
}

func NewTerraformResolver(services []*terraform.FastlyService) []Resolver {
	var resolvers []Resolver
	for _, v := range services {
		s := &TerraformResolver{
			ServiceName: v.Name,
		}
		for _, vcl := range v.Vcls {
			if vcl.Main {
				s.Main = &VCL{
					Name: vcl.Name,
					Data: vcl.Content,
				}
			} else {
				s.Modules = append(s.Modules, &VCL{
					Name: vcl.Name,
					Data: vcl.Content,
				})
			}
		}
		resolvers = append(resolvers, s)
	}
	return resolvers
}

func (s *TerraformResolver) Name() string {
	return s.ServiceName
}

func (s *TerraformResolver) MainVCL() (*VCL, error) {
	return s.Main, nil
}

func (s *TerraformResolver) Resolve(module string) (*VCL, error) {
	for i := range s.Modules {
		if s.Modules[i].Name == module {
			return s.Modules[i], nil
		}
	}

	return nil, errors.New(fmt.Sprintf("Failed to resolve include file: %s.vcl", module))
}
