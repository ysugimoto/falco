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
	return append(
		f.Dictionaries,
		append(f.Acls, f.Backends...)...,
	)
}
