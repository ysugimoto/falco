package snippet

// Remote resources mapping structs

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

type DirectorType int8

const (
	Random DirectorType = iota + 1
	Hash
	Client
	Shield // shield director type is special type for Origin-Shielding on Faslty configuration
)

type Director struct {
	Type     int
	Name     string
	Backends []string
	Retries  int
	Quorum   int
}

/*
  {
    "type": "REQUEST",
    "statement": "req.url.path == \"/.well-known/change-password\"",
    "service_id": "0jkUgZ76zN3lJzVa1ZhaM9",
    "priority": "10",
    "version": "204",
    "comment": "",
    "name": "well-known-change-password",
    "created_at": "2021-01-25T08:06:34Z",
    "deleted_at": null,
    "updated_at": "2025-05-26T06:38:31Z"
  }
*/

type Phase string

const (
	RequestPhase  Phase = "REQUEST"
	CachePhase    Phase = "CACHE"
	ResponsePhase Phase = "RESPONSE"
)

type Condition struct {
	Type      Phase
	Statement string
	Priority  int64
	Name      string
}
