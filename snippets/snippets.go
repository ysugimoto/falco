package snippets

type SnippetItem struct {
	Data string
	Name string
}

type Snippets struct {
	Dictionaries     []SnippetItem
	Acls             []SnippetItem
	Backends         []SnippetItem
	Directors        []SnippetItem
	ScopedSnippets   map[string][]SnippetItem
	IncludeSnippets  map[string]SnippetItem
	LoggingEndpoints map[string]struct{}
}

func (s *Snippets) EmbedSnippets() []SnippetItem {
	var snippets []SnippetItem

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
