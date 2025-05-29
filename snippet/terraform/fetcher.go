package terraform

import (
	"strconv"

	"github.com/ysugimoto/falco/snippet"
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

func (f *TerraformFetcher) Backends() ([]*snippet.Backend, error) {
	var b []*snippet.Backend
	for _, s := range f.filterService() {
		for _, backend := range s.Backends {
			b = append(b, &snippet.Backend{
				Name:    backend.Name,
				Shield:  backend.Shield,
				Address: backend.Address,
			})
		}
	}
	return b, nil
}

func (f *TerraformFetcher) Dictionaries() ([]*snippet.Dictionary, error) {
	var d []*snippet.Dictionary
	for _, s := range f.filterService() {
		for _, dict := range s.Dictionaries {
			var items []*snippet.DictionaryItem

			if dict.Items != nil {
				items = make([]*snippet.DictionaryItem, len(dict.Items))
				for i, item := range dict.Items {
					items[i] = &snippet.DictionaryItem{
						Key:   item.Key,
						Value: item.Value,
					}
				}
			}

			d = append(d, &snippet.Dictionary{
				Name:  dict.Name,
				Items: items,
			})
		}
	}
	return d, nil
}

func (f *TerraformFetcher) Acls() ([]*snippet.Acl, error) {
	var a []*snippet.Acl
	for _, s := range f.filterService() {
		for _, sACL := range s.Acls {
			var entries []*snippet.AclEntry

			if sACL.Entries != nil {
				entries = make([]*snippet.AclEntry, len(sACL.Entries))
				for i, entry := range sACL.Entries {
					ae := &snippet.AclEntry{
						Ip:      entry.Ip,
						Comment: entry.Comment,
					}
					if subnet, err := strconv.ParseInt(entry.Subnet, 10, 64); err == nil {
						ae.Subnet = &subnet
					}
					if entry.Negated {
						ae.Negated = "!"
					}
					entries[i] = ae
				}
			}
			a = append(a, &snippet.Acl{
				Name:    sACL.Name,
				Entries: entries,
			})
		}
	}
	return a, nil
}

func (f *TerraformFetcher) Directors() ([]*snippet.Director, error) {
	var d []*snippet.Director
	for _, s := range f.filterService() {
		for _, director := range s.Directors {
			d = append(d, &snippet.Director{
				Type:     director.Type,
				Name:     director.Name,
				Backends: director.Backends,
				Retries:  *director.Retries,
				Quorum:   *director.Quorum,
			})
		}
	}
	return d, nil
}

func (f *TerraformFetcher) Snippets() ([]*snippet.VCLSnippet, error) {
	var v []*snippet.VCLSnippet
	for _, s := range f.filterService() {
		for _, vcl := range s.Snippets {
			v = append(v, &snippet.VCLSnippet{
				Name:     vcl.Name,
				Type:     vcl.Type,
				Content:  vcl.Content,
				Priority: vcl.Priority,
			})
		}
	}
	return v, nil
}

func (f *TerraformFetcher) LoggingEndpoints() ([]string, error) {
	var v []string
	for _, s := range f.filterService() {
		v = append(v, s.LoggingEndpoints...)
	}
	return v, nil
}

var _ snippet.Fetcher = (*TerraformFetcher)(nil)
