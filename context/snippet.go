package context

type FastlySnippetItem struct {
	Data string
	Name string
}

type FastlySnippet struct {
	Dictionaries    []FastlySnippetItem
	Acls            []FastlySnippetItem
	Backends        []FastlySnippetItem
	ScopedSnippets  map[string][]FastlySnippetItem
	IncludeSnippets map[string]FastlySnippetItem
}

func (f *FastlySnippet) EmbedSnippets() []FastlySnippetItem {
	var snippets []FastlySnippetItem

	// Embed Dictionaries
	snippets = append(snippets, f.Dictionaries...)
	// Embed Acls
	snippets = append(snippets, f.Acls...)
	// Embed Backends
	snippets = append(snippets, f.Backends...)

	// And also we need to embed VCL snippets which is registered as "init" type
	if scoped, ok := f.ScopedSnippets["init"]; ok {
		snippets = append(snippets, scoped...)
	}

	return snippets
}
