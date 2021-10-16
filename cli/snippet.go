package main

import (
	"bytes"
	"context"
	"fmt"

	"net/http"
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

type Snippet struct {
	client           *remote.FastlyClient
	edgeDictinalries []string
	vclSnippets      []*remote.VCLSnippet
}

func NewSnippet(serviceId, apiKey string) *Snippet {
	return &Snippet{
		client: remote.NewFastlyClient(http.DefaultClient, serviceId, apiKey),
	}
}

func (s *Snippet) Fetch(ctx context.Context) error {
	// Fetch latest version
	version, err := s.client.LatestVersion(ctx)
	if err != nil {
		return fmt.Errorf("Failed to get latest version %w", err)
	}

	write(white, "Fetching Edge Dictionaries...")
	s.edgeDictinalries, err = s.fetchEdgeDictionary(ctx, version)
	if err != nil {
		return err
	}
	writeln(white, "Done")

	write(white, "Fetching VCL snippets...")
	s.vclSnippets, err = s.fetchVCLSnippets(ctx, version)
	if err != nil {
		return err
	}
	writeln(white, "Done")

	return nil
}

// Fetch remote Edge dictionary items
func (s *Snippet) fetchEdgeDictionary(ctx context.Context, version int64) ([]string, error) {
	dicts, err := s.client.ListEdgeDictionaries(ctx, version)
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

// Fetch remote VCL snippets
func (s *Snippet) fetchVCLSnippets(ctx context.Context, version int64) ([]*remote.VCLSnippet, error) {
	snippets, err := s.client.ListVCLSnippets(ctx)
	if err != nil {
		return nil, err
	}

	return snippets, nil
}
