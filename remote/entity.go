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

type AccessControl struct {
	Id      string `json:"id"`
	Name    string `json:"name"`
	Entries []*AccessControlEntry
}

type AccessControlEntry struct {
	Ip      string `json:"ip"`
	Negated string `json:"negated"`
	Subnet  *int64 `json:"subnet"`
	Comment string `json:"comment"`
}

type Backend struct {
	Name   string  `json:"name"`
	Shield *string `json:"shield"`
}

type DirectorType int8

const (
	Random DirectorType = iota + 1
	Hash
	Client
)

type Director struct {
	Name     string       `json:"name"`
	Type     DirectorType `json:"type"`
	Backends []string     `json:"backends"`
}
