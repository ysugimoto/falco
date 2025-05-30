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

type Action string

const (
	SetAction      Action = "set"
	AppendAction   Action = "append"
	DeleteAction   Action = "delete"
	RegexAction    Action = "regex"
	RegexAllAction Action = "regex_repeat"
)

type Header struct {
	Type         Phase
	Action       Action
	Name         string
	IgnoreIfSet  bool
	Condition    *string
	Priority     int64
	Source       string
	Destination  string
	Regex        string
	Substitution string

	// This field value will be assigned on rendering
	ConditionExpression string
}
