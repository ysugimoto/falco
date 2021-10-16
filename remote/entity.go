package remote

type Version struct {
	Number int64 `json:"number"`
}

type EdgeDictionary struct {
	Id    string `json:"id"`
	Name  string `json:"name"`
	Items []*EdgeDictionaryItem
}

type EdgeDictionaryItem struct {
	Key   string `json:"item_key"`
	Value string `json:"item_value"`
}

type SnippetType string

const (
	SnippetTypeInit    SnippetType = "init"
	SnippetTypeRecv    SnippetType = "recv"
	SnippetTypeHit     SnippetType = "hit"
	SnippetTypeMiss    SnippetType = "miss"
	SnippetTypePass    SnippetType = "pass"
	SnippetTypeFetch   SnippetType = "fetch"
	SnippetTypeError   SnippetType = "error"
	SnippetTypeDeliver SnippetType = "deliver"
	SnippetTypeLog     SnippetType = "log"
	SnippetTypeHash    SnippetType = "hash"
	SnippetTypeNone    SnippetType = "none"
)

type VCLSnippet struct {
	Id      string      `json:"id"`
	Dynamic string      `json:"dynamic"`
	Type    SnippetType `json:"type"`
	Content *string     `json:"content"`
	Name    string      `json:"name"`
}
