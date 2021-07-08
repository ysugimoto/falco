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
