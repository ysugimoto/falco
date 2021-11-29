package main

import (
	"bytes"
	_context "context"
	"fmt"
	"strings"

	"net/http"
	"text/template"

	"github.com/ysugimoto/falco/context"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/linter"
	"github.com/ysugimoto/falco/parser"
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

type Snippet struct {
	client   *remote.FastlyClient
	snippets []string
}

func NewSnippet(serviceId, apiKey string) *Snippet {
	return &Snippet{
		client: remote.NewFastlyClient(http.DefaultClient, serviceId, apiKey),
	}
}

func (s *Snippet) Compile(ctx *context.Context) error {
	vcl, err := parser.New(lexer.NewFromString(strings.Join(s.snippets, "\n"))).ParseVCL()
	if err != nil {
		return err
	}
	l := linter.New()
	l.Lint(vcl, ctx, false)
	return nil
}

func (s *Snippet) Fetch(c _context.Context) error {
	// Fetch latest version
	version, err := s.client.LatestVersion(c)
	if err != nil {
		return fmt.Errorf("Failed to get latest version %w", err)
	}
	write(white, "Fetching Edge Dictionaries...")
	dicts, err := s.fetchEdgeDictionary(c, version)
	if err != nil {
		return err
	}
	writeln(white, "Done")
	s.snippets = append(s.snippets, dicts...)

	write(white, "Fatching Access Control Lists...")
	acls, err := s.fetchAccessControl(c, version)
	if err != nil {
		return err
	}
	writeln(white, "Done")
	s.snippets = append(s.snippets, acls...)
	return nil
}

// Fetch remote Edge dictionary items
func (s *Snippet) fetchEdgeDictionary(c _context.Context, version int64) ([]string, error) {
	dicts, err := s.client.ListEdgeDictionaries(c, version)
	if err != nil {
		return nil, fmt.Errorf("Failed to get edge dictionaries for version %w", err)
	}

	tmpl, err := template.New("table").Parse(tableTemplate)
	if err != nil {
		return nil, fmt.Errorf("Failed to compilte table template: %w", err)
	}

	var snippets []string
	for _, dict := range dicts {
		buf := new(bytes.Buffer)
		if err := tmpl.Execute(buf, dict); err != nil {
			return nil, fmt.Errorf("Failed to render table template: %w", err)
		}
		snippets = append(snippets, buf.String())
	}
	return snippets, nil
}

// Fetch remote Access Control entries
func (s *Snippet) fetchAccessControl(c _context.Context, version int64) ([]string, error) {
	acls, err := s.client.ListAccessControlLists(c, version)
	if err != nil {
		return nil, fmt.Errorf("Failed to get access control lists for version %w", err)
	}

	tmpl, err := template.New("acl").Parse(aclTemplate)
	if err != nil {
		return nil, fmt.Errorf("Failed to compilte acl template: %w", err)
	}

	var snippets []string
	for _, a := range acls {
		buf := new(bytes.Buffer)
		if err := tmpl.Execute(buf, a); err != nil {
			return nil, fmt.Errorf("Failed to render table template: %w", err)
		}
		snippets = append(snippets, buf.String())
	}
	return snippets, nil
}
