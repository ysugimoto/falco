package snippet

type AclEntry struct {
	Ip      string
	Negated string
	Subnet  *int64
	Comment string
}

type Acl struct {
	Name    string
	Entries []*AclEntry
}

type DictionaryItem struct {
	Key   string
	Value string
}

type Dictionary struct {
	Name  string
	Items []*DictionaryItem
}

// TODO(davinci26): We can unmarshall all the properties from the TF file
// and lint them to make sure they have sane values.
type Backend struct {
	Name    string
	Shield  *string
	Address *string
}

type VCLSnippet struct {
	Name     string
	Type     string
	Content  string
	Priority int64
}

type Director struct {
	Type     int
	Name     string
	Backends []string
	Retries  int
	Quorum   int
}

type DirectorType int8

const (
	Random DirectorType = iota + 1
	Hash
	Client
	Shield // shield director type is special type for Origin-Shielding on Faslty configuration
)
