package terraform

import (
	"github.com/ysugimoto/falco/types"
)

type TerraformFetcher struct {
	services []*FastlyService
}

func NewTerraformFetcher(s []*FastlyService) *TerraformFetcher {
	return &TerraformFetcher{
		services: s,
	}
}

func (f *TerraformFetcher) Backends() ([]*types.RemoteBackend, error) {
	var b []*types.RemoteBackend
	for _, s := range f.services {
		for _, serviceBackend := range s.Backends {
			b = append(b, &types.RemoteBackend{
				Name:   serviceBackend.Name,
				Shield: serviceBackend.Shield,
			})
		}
	}
	return b, nil
}

func (f *TerraformFetcher) Dictionaries() ([]*types.RemoteDictionary, error) {
	var d []*types.RemoteDictionary
	for _, s := range f.services {
		for _, sDictionary := range s.Dictionaries {
			d = append(d, &types.RemoteDictionary{
				Name: sDictionary.Name,
			})
		}
	}
	return d, nil
}

func (f *TerraformFetcher) Acls() ([]*types.RemoteAcl, error) {
	var a []*types.RemoteAcl
	for _, s := range f.services {
		for _, sACL := range s.Acls {
			a = append(a, &types.RemoteAcl{
				Name: sACL.Name,
			})
		}
	}
	return a, nil
}
