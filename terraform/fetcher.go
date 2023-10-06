package terraform

import (
	"github.com/ysugimoto/falco/types"
)

type TerraformFetcher struct {
	services    []*FastlyService
	currentName string
}

func NewTerraformFetcher(s []*FastlyService) *TerraformFetcher {
	return &TerraformFetcher{
		services: s,
	}
}

func (f *TerraformFetcher) SetName(name string) {
	f.currentName = name
}

func (f *TerraformFetcher) filterService() []*FastlyService {
	if f.currentName == "" {
		return f.services
	}
	for _, s := range f.services {
		if s.Name == f.currentName {
			return []*FastlyService{s}
		}
	}
	return []*FastlyService{}
}

func (f *TerraformFetcher) Backends() ([]*types.RemoteBackend, error) {
	var b []*types.RemoteBackend
	for _, s := range f.filterService() {
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
	for _, s := range f.filterService() {
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
	for _, s := range f.filterService() {
		for _, sACL := range s.Acls {
			a = append(a, &types.RemoteAcl{
				Name: sACL.Name,
			})
		}
	}
	return a, nil
}

func (f *TerraformFetcher) Snippets() ([]*types.RemoteVCL, error) {
	var v []*types.RemoteVCL
	for _, s := range f.filterService() {
		for _, vcl := range s.Snippets {
			v = append(v, &types.RemoteVCL{
				Name:     vcl.Name,
				Type:     vcl.Type,
				Content:  vcl.Content,
				Priority: vcl.Priority,
			})
		}
	}
	return v, nil
}
