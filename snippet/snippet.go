package snippet

type Item struct {
	Data string
	Name string
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

	// expose items, access from external package
	ScopedSnippets  ScopedSnippets
	IncludeSnippets IncludeSnippets

	// Currently no use
	LoggingEndpoints LoggingEndpoints
}

func (s *Snippets) EmbedSnippets() []Item {
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

	return snippets
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
