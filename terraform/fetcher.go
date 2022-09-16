package terraform

import (
	"github.com/ysugimoto/falco/remote"
)

type TerraformFetcher struct {
	services []*FastlyService
}

func NewTerraformFetcher(s []*FastlyService) *TerraformFetcher {
	return &TerraformFetcher{
		services: s,
	}
}

func (f *TerraformFetcher) Backends() ([]*remote.Backend, error) {
	var b []*remote.Backend
	for _, s := range f.services {
		for _, serviceBackend := range s.Backends {
			b = append(b, &remote.Backend{
				Name: serviceBackend.Name,
			})
		}
	}
	return b, nil
}

func (f *TerraformFetcher) Dictionaries() ([]*remote.EdgeDictionary, error) {
	var d []*remote.EdgeDictionary
	for _, s := range f.services {
		for _, sDictionary := range s.Dictionaries {
			d = append(d, &remote.EdgeDictionary{
				Name: sDictionary.Name,
			})
		}
	}
	return d, nil
}

func (f *TerraformFetcher) Acls() ([]*remote.AccessControl, error) {
	var a []*remote.AccessControl
	for _, s := range f.services {
		for _, sACL := range s.Acls {
			a = append(a, &remote.AccessControl{
				Name: sACL.Name,
			})
		}
	}
	return a, nil
}
