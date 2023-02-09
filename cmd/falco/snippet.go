package main

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"text/template"

	"github.com/ysugimoto/falco/context"
	"github.com/ysugimoto/falco/remote"
	"github.com/ysugimoto/falco/types"
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

var invalid *regexp.Regexp

func init() {
	invalid = regexp.MustCompile(`\W`)
}

func TerraformBackendNameSanitizer(name string) string {
	s := invalid.ReplaceAllString(name, "_")
	return s
}

type Snippet struct {
	fetcher Fetcher
}

func NewSnippet(f Fetcher) *Snippet {
	return &Snippet{
		fetcher: f,
	}
}

func (s *Snippet) Fetch() (*context.FastlySnippet, error) {
	var fs context.FastlySnippet
	var err error

	write(white, "Fetching Edge Dictionaries...")
	fs.Dictionaries, err = s.fetchEdgeDictionary()
	if err != nil {
		return nil, err
	}
	writeln(white, "Done")

	write(white, "Fatching Access Control Lists...")
	fs.Acls, err = s.fetchAccessControl()
	if err != nil {
		return nil, err
	}
	writeln(white, "Done")

	write(white, "Fatching Backends...")
	fs.Backends, err = s.fetchBackend()
	if err != nil {
		return nil, err
	}
	writeln(white, "Done")

	write(white, "Fatching Snippets...")
	fs.ScopedSnippets, fs.IncludeSnippets, err = s.fetchVCLSnippets()
	if err != nil {
		return nil, err
	}
	writeln(white, "Done")

	return &fs, nil
}

// Fetch remote Edge dictionary items
func (s *Snippet) fetchEdgeDictionary() ([]context.FastlySnippetItem, error) {
	dicts, err := s.fetcher.Dictionaries()
	if err != nil {
		return nil, fmt.Errorf("Failed to get edge dictionaries %w", err)
	}

	tmpl, err := template.New("table").Parse(tableTemplate)
	if err != nil {
		return nil, fmt.Errorf("Failed to compilte table template: %w", err)
	}

	var snippets []context.FastlySnippetItem
	for _, dict := range dicts {
		buf := new(bytes.Buffer)
		if err := tmpl.Execute(buf, dict); err != nil {
			return nil, fmt.Errorf("Failed to render table template: %w", err)
		}
		snippets = append(snippets, context.FastlySnippetItem{
			Name: fmt.Sprintf("EdgeDictionary:%s", dict.Name),
			Data: buf.String(),
		})
	}
	return snippets, nil
}

// Fetch remote Access Control entries
func (s *Snippet) fetchAccessControl() ([]context.FastlySnippetItem, error) {
	acls, err := s.fetcher.Acls()
	if err != nil {
		return nil, fmt.Errorf("Failed to get ACLs: %w", err)
	}

	tmpl, err := template.New("acl").Parse(aclTemplate)
	if err != nil {
		return nil, fmt.Errorf("Failed to compile acl template: %w", err)
	}

	var snippets []context.FastlySnippetItem
	for _, a := range acls {
		buf := new(bytes.Buffer)
		if err := tmpl.Execute(buf, a); err != nil {
			return nil, fmt.Errorf("Failed to render acl template: %w", err)
		}
		snippets = append(snippets, context.FastlySnippetItem{
			Name: fmt.Sprintf("ACL:%s", a.Name),
			Data: buf.String(),
		})
	}
	return snippets, nil
}

func (s *Snippet) fetchBackend() ([]context.FastlySnippetItem, error) {
	var snippets []context.FastlySnippetItem
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
		b.Name = TerraformBackendNameSanitizer(b.Name)
		if err := backTmpl.Execute(buf, b); err != nil {
			return nil, fmt.Errorf("failed to render backend template: %w", err)
		}
		snippets = append(snippets, context.FastlySnippetItem{
			Name: fmt.Sprintf("BACKEND:%s", b.Name),
			Data: buf.String(),
		})
	}

	// Generate director snippet only when at least one backend is declared
	if len(backends) > 0 {
		directors, err := s.renderBackendShields(backends)
		if err != nil {
			return nil, err
		}
		snippets = append(snippets, directors...)
	}

	return snippets, nil
}

func (s *Snippet) renderBackendShields(backends []*types.RemoteBackend) ([]context.FastlySnippetItem, error) {
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
		if b.Shield != nil && *b.Shield != "" {
			shieldDirectors[*b.Shield] = struct{}{}
		}
	}

	var snippets []context.FastlySnippetItem
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
		snippets = append(snippets, context.FastlySnippetItem{
			Name: fmt.Sprintf("DIRECTOR:%s", d.Name),
			Data: buf.String(),
		})
	}

	return snippets, nil
}

func (s *Snippet) fetchVCLSnippets() (
	map[string][]context.FastlySnippetItem,
	map[string]context.FastlySnippetItem,
	error,
) {

	snippets, err := s.fetcher.Snippets()
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get VCL snippets: %w", err)
	}

	// Sort by priority
	sort.Slice(snippets, func(i, j int) bool {
		return snippets[i].Priority > snippets[j].Priority
	})

	scoped := make(map[string][]context.FastlySnippetItem)
	include := make(map[string]context.FastlySnippetItem)
	for _, snip := range snippets {
		// "none" type means that user could include the snippet arbitrary
		if snip.Type == "none" {
			include[snip.Name] = context.FastlySnippetItem{
				Name: snip.Name,
				Data: snip.Content,
			}
			continue
		}
		// Otherwise, factory with type (phase) name
		if _, ok := scoped[snip.Type]; !ok {
			scoped[snip.Type] = []context.FastlySnippetItem{}
		}
		scoped[snip.Type] = append(scoped[snip.Type], context.FastlySnippetItem{
			Name: snip.Name,
			Data: snip.Content,
		})
	}

	return scoped, include, nil
}
