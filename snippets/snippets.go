package snippets

type SnippetItem struct {
	Data string
	Name string
}

type Snippets struct {
	Dictionaries     []SnippetItem
	Acls             []SnippetItem
	Backends         []SnippetItem
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

	// And also we need to embed VCL snippets which is registered as "init" type
	if scoped, ok := s.ScopedSnippets["init"]; ok {
		snippets = append(snippets, scoped...)
	}

	return snippets
}
