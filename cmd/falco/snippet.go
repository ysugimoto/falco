package main

import (
	"bytes"
	"fmt"
	"strings"

	"text/template"

	"github.com/ysugimoto/falco/remote"
)

var tableTemplate = `
table {{ .Name }} {
	{{- range .Items }}
	"{{ .Key }}": "{{ .Value }}",
	{{- end }}
}
`

var aclTemplate = `
acl {{ .Name }} {
	{{- range .Entries }}
	{{ if .Negated }}!{{ end }}"{{ .Ip }}"{{ if .Subnet }}/{{ .Subnet }}{{ end }};{{ if .Comment }}  # {{ .Comment }}{{ end }}
	{{- end }}
}
`

var backendTemplate = `
backend F_{{ .Name }} {}
`

var directorTemplate = `
director {{ .Name }} {{ .Type | printtype }} {
	{{- range .Backends }}
	{ .backend = {{ . }}; .weight = 1; }
	{{- end }}
}
`

type snippetItem struct {
	Data string
	Name string
}

type Snippet struct {
	fetcher Fetcher
}

func NewSnippet(f Fetcher) *Snippet {
	return &Snippet{
		fetcher: f,
	}
}

func (s *Snippet) Fetch() ([]snippetItem, error) {
	var snippets []snippetItem

	write(white, "Fetching Edge Dictionaries...")
	dicts, err := s.fetchEdgeDictionary()
	if err != nil {
		return nil, err
	}
	writeln(white, "Done")
	snippets = append(snippets, dicts...)

	write(white, "Fatching Access Control Lists...")
	acls, err := s.fetchAccessControl()
	if err != nil {
		return nil, err
	}
	writeln(white, "Done")
	snippets = append(snippets, acls...)

	write(white, "Fatching Backends...")
	backends, err := s.fetchBackend()
	if err != nil {
		return nil, err
	}
	writeln(white, "Done")
	snippets = append(snippets, backends...)

	return snippets, nil
}

// Fetch remote Edge dictionary items
func (s *Snippet) fetchEdgeDictionary() ([]snippetItem, error) {
	dicts, err := s.fetcher.Dictionaries()
	if err != nil {
		return nil, fmt.Errorf("Failed to get edge dictionaries %w", err)
	}

	tmpl, err := template.New("table").Parse(tableTemplate)
	if err != nil {
		return nil, fmt.Errorf("Failed to compilte table template: %w", err)
	}

	var snippets []snippetItem
	for _, dict := range dicts {
		buf := new(bytes.Buffer)
		if err := tmpl.Execute(buf, dict); err != nil {
			return nil, fmt.Errorf("Failed to render table template: %w", err)
		}
		snippets = append(snippets, snippetItem{
			Name: fmt.Sprintf("EdgeDictionary:%s", dict.Name),
			Data: buf.String(),
		})
	}
	return snippets, nil
}

// Fetch remote Access Control entries
func (s *Snippet) fetchAccessControl() ([]snippetItem, error) {
	acls, err := s.fetcher.Acls()
	if err != nil {
		return nil, fmt.Errorf("Failed to get ACLs: %w", err)
	}

	tmpl, err := template.New("acl").Parse(aclTemplate)
	if err != nil {
		return nil, fmt.Errorf("Failed to compile acl template: %w", err)
	}

	var snippets []snippetItem
	for _, a := range acls {
		buf := new(bytes.Buffer)
		if err := tmpl.Execute(buf, a); err != nil {
			return nil, fmt.Errorf("Failed to render table template: %w", err)
		}
		snippets = append(snippets, snippetItem{
			Name: fmt.Sprintf("ACL:%s", a.Name),
			Data: buf.String(),
		})
	}
	return snippets, nil
}

func (s *Snippet) fetchBackend() ([]snippetItem, error) {
	var snippets []snippetItem
	backends, err := s.fetcher.Backends()
	if err != nil {
		return nil, fmt.Errorf("Failed to get Backends: %w", err)
	}
	if len(backends) == 0 {
		return snippets, nil
	}
	backTmpl, err := template.New("backend").Parse(backendTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to compile backend template: %w", err)
	}

	for _, b := range backends {
		buf := new(bytes.Buffer)
		if err := backTmpl.Execute(buf, b); err != nil {
			return nil, fmt.Errorf("failed to render backend template: %w", err)
		}
		snippets = append(snippets, snippetItem{
			Name: fmt.Sprintf("BACKEND:%s", b.Name),
			Data: buf.String(),
		})
	}

	directors, err := s.renderBackendShields(backends)
	if err != nil {
		return nil, err
	}
	snippets = append(snippets, directors...)

	return snippets, nil
}

func (s *Snippet) renderBackendShields(backends []*remote.Backend) ([]snippetItem, error) {
	printType := func(dtype remote.DirectorType) string {
		switch dtype {
		case remote.Random:
			return "random"
		case remote.Hash:
			return "hash"
		case remote.Client:
			return "client"
		}
		return ""
	}
	dirTmpl, err := template.New("director").
		Funcs(template.FuncMap{"printtype": printType}).
		Parse(directorTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to compile director template: %w", err)
	}

	shieldDirectors := make(map[string]struct{})
	for _, b := range backends {
		if b.Shield != nil {
			shieldDirectors[*b.Shield] = struct{}{}
		}
	}

	var snippets []snippetItem
	// We need to pick an arbitrary backend to avoid an undeclared linter error
	shieldBackend := "F_" + backends[0].Name
	for sd := range shieldDirectors {
		d := remote.Director{
			Name:     "ssl_shield_" + strings.ReplaceAll(sd, "-", "_"),
			Type:     remote.Random,
			Backends: []string{shieldBackend},
		}
		buf := new(bytes.Buffer)
		if err := dirTmpl.Execute(buf, d); err != nil {
			return nil, fmt.Errorf("failed to render director template: %w", err)
		}
		snippets = append(snippets, snippetItem{
			Name: fmt.Sprintf("DIRECTOR:%s", d.Name),
			Data: buf.String(),
		})
	}

	return snippets, nil
}
