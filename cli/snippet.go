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
	l.Lint(vcl, ctx)
	return nil
}

func (s *Snippet) Fetch(c _context.Context) error {
	write(white, "Fetching Edge Dictionaries...")
	dicts, err := s.fetchEdgeDictionary(c)
	if err != nil {
		return err
	}
	writeln(white, "Done")
	s.snippets = append(s.snippets, dicts...)
	return nil
}

// Fetch remote Edge dictionary items
func (s *Snippet) fetchEdgeDictionary(c _context.Context) ([]string, error) {
	// Fetch latest version
	version, err := s.client.LatestVersion(c)
	if err != nil {
		return nil, fmt.Errorf("Failed to get latest version %w", err)
	}

	dicts, err := s.client.ListEdgeDictionaries(c, version)
	if err != nil {
		return nil, fmt.Errorf("Failed to get latest version %w", err)
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
