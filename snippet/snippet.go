package snippet

import (
	"github.com/pkg/errors"
)

type Item struct {
	Data     string
	Name     string
	Priority int64
}

// map type aliases
type (
	ScopedSnippets   map[string][]Item
	IncludeSnippets  map[string]Item
	LoggingEndpoints map[string]struct{}
)

type Snippets struct {
	// Store fetched resources
	dictionaries []Item
	acls         []Item
	backends     []Item
	directors    []Item

	// Lazy rendering snippets
	conditions map[string]*Condition
	headers    []*Header

	// expose items, access from external package
	ScopedSnippets  ScopedSnippets
	IncludeSnippets IncludeSnippets

	// Currently no use
	LoggingEndpoints LoggingEndpoints
}

func (s *Snippets) EmbedSnippets() ([]Item, error) {
	var snippets []Item

	// Embed Dictionaries
	snippets = append(snippets, s.dictionaries...)
	// Embed Acls
	snippets = append(snippets, s.acls...)
	// Embed Backends
	snippets = append(snippets, s.backends...)
	// Embed Directors
	// Note that director must be placed after backends
	// because director refers to backend
	snippets = append(snippets, s.directors...)

	// And also we need to embed VCL snippets which is registered as "init" type
	if scoped, ok := s.ScopedSnippets["init"]; ok {
		snippets = append(snippets, scoped...)
	}

	// Render header snippets - embedded on extracting Fastly macros
	for i := range s.headers {
		if err := s.renderHeaderSnippet(s.headers[i]); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	return snippets, nil
}

// Fastly logging endpoints is not used on linting and interpreter,
// but we need to be able to factory all endpoints for future works.
// Fastly's logging endpoints API is divided for each services like BigQuery, S3, etc..
// It means we need to make many API calls so implement as Snippets pointer method.
func (s *Snippets) FetchLoggingEndpoint(fetcher Fetcher) error {
	endpoints, err := fetcher.LoggingEndpoints()
	if err != nil {
		return err
	}

	// Convert map to key access
	for i := range endpoints {
		s.LoggingEndpoints[endpoints[i]] = struct{}{}
	}
	return nil
}

func (s *Snippets) renderHeaderSnippet(h *Header) error {
	var snip *Item
	var err error

	if h.Condition == nil {
		// If condition is nil, don't need to look up condition map. enable to render directly
		snip, err = renderHeader(h)
	} else {
		// Otherwise, look up condtion map and get condition expression
		cond, ok := s.conditions[*h.Condition]
		if !ok {
			err = errors.New("Condition " + *h.Condition + " is not found")
		} else {
			h.ConditionExpression = cond.Statement
			snip, err = renderHeader(h)
		}
	}
	if err != nil {
		return errors.WithStack(err)
	}

	// Assign snippet which corresponds to scope
	var scope string
	switch h.Type {
	case RequestPhase:
		scope = "recv"
	case CachePhase:
		scope = "fetch"
	case ResponsePhase:
		scope = "deliver"
	}

	if _, ok := s.ScopedSnippets[scope]; !ok {
		s.ScopedSnippets[scope] = []Item{}
	}
	s.ScopedSnippets[scope] = append(s.ScopedSnippets[scope], *snip)
	return nil
}
