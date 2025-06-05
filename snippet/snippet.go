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

func (s ScopedSnippets) Add(scope string, item Item) {
	if _, ok := s[scope]; !ok {
		s[scope] = []Item{}
	}
	s[scope] = append(s[scope], item)
}

type Snippets struct {
	// Store fetched resources
	Dictionaries []Item `json:"dictionaries"`
	Acls         []Item `json:"acls"`
	Backends     []Item `json:"backends"`
	Directors    []Item `json:"directors"`

	// Lazy rendering snippets
	Conditions      map[string]*Condition `json:"conditions"`
	Headers         []*Header             `json:"headers"`
	ResponseObjects []*ResponseObject     `json:"responseObjects"`

	// expose items, access from external package
	ScopedSnippets  ScopedSnippets  `json:"scoped"`
	IncludeSnippets IncludeSnippets `json:"include"`

	// Currently no use
	LoggingEndpoints LoggingEndpoints `json:"logging"`
}

func (s *Snippets) EmbedSnippets() ([]Item, error) {
	var snippets []Item

	// Embed Dictionaries
	snippets = append(snippets, s.Dictionaries...)
	// Embed Acls
	snippets = append(snippets, s.Acls...)
	// Embed Backends
	snippets = append(snippets, s.Backends...)
	// Embed Directors
	// Note that director must be placed after backends
	// because director refers to backend
	snippets = append(snippets, s.Directors...)

	// And also we need to embed VCL snippets which is registered as "init" type
	if scoped, ok := s.ScopedSnippets["init"]; ok {
		snippets = append(snippets, scoped...)
	}

	// Render embedded snippets on extracting Fastly macros
	for i := range s.Headers {
		if err := s.renderHeaderSnippet(s.Headers[i]); err != nil {
			return nil, errors.WithStack(err)
		}
	}
	// Response object is handled at error directive,
	// so use error statement with internal status code like:
	//
	// error 900 "Fastly Internal";
	//
	// The Fastly internal status code starts 9XX numbers.
	internalStatusCode := 900
	for i := range s.ResponseObjects {
		if err := s.renderResponseObjectSnippet(s.ResponseObjects[i], internalStatusCode); err != nil {
			return nil, errors.WithStack(err)
		}
		internalStatusCode++
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
		cond, ok := s.Conditions[*h.Condition]
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

func (s *Snippets) renderResponseObjectSnippet(r *ResponseObject, statusCode int) error {
	var snip *Item
	var err error

	// Render condition
	scope := "recv"
	r.StatusCode = statusCode
	switch {
	case r.RequestCondition != "":
		cond, ok := s.Conditions[r.RequestCondition]
		if !ok {
			return errors.New("Condition " + r.RequestCondition + " is not found")
		}
		r.ConditionExpression = cond.Statement
	case r.CacheCondition != "":
		cond, ok := s.Conditions[r.CacheCondition]
		if !ok {
			return errors.New("Condition " + r.CacheCondition + " is not found")
		}
		r.ConditionExpression = cond.Statement
		scope = "fetch"
	}

	condition, err := renderResponseObjectCondition(r)
	if err != nil {
		return errors.WithStack(err)
	}
	if _, ok := s.ScopedSnippets[scope]; !ok {
		s.ScopedSnippets[scope] = []Item{}
	}
	s.ScopedSnippets[scope] = append(s.ScopedSnippets[scope], *condition)

	// And also render response object
	snip, err = renderResponseObject(r)
	if err != nil {
		return errors.WithStack(err)
	}
	if _, ok := s.ScopedSnippets["error"]; !ok {
		s.ScopedSnippets["error"] = []Item{}
	}
	s.ScopedSnippets["error"] = append(s.ScopedSnippets["error"], *snip)
	return nil
}
