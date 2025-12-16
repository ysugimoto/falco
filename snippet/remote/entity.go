package remote

type Version struct {
	Number int64 `json:"number"`
}

type EdgeDictionary struct {
	Id        string `json:"id"`
	Name      string `json:"name"`
	WriteOnly bool   `json:"write_only"`
	Items     []*EdgeDictionaryItem
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
	Name    string  `json:"name"`
	Shield  *string `json:"shield"`
	Address *string `json:"address"`
}

type Director struct {
	Name     string   `json:"name"`
	Type     int      `json:"type"`
	Backends []string `json:"backends"`
	Retries  int      `json:"retries"`
	Quorum   int      `json:"quorum"`
}

type VCLSnippet struct {
	Id       string  `json:"id"`
	Name     string  `json:"name"`
	Dynamic  string  `json:"dynamic"`
	Type     string  `json:"type"`
	Priority string  `json:"priority"`
	Content  *string `json:"content"`
}

type Condition struct {
	Type      string `json:"type"`
	Statement string `json:"statement"`
	Priority  string `json:"priority"`
	Name      string `json:"name"`
}

type Header struct {
	Regex             string  `json:"regex"`
	Type              string  `json:"type"`
	IgnoreIfSet       string  `json:"ignore_if_set"`
	RequestCondition  *string `json:"request_condition"`
	CacheCondition    *string `json:"cache_condition"`
	ResponseCondition *string `json:"response_condition"`
	Source            string  `json:"src"`
	Destination       string  `json:"dst"`
	Priority          string  `json:"priority"`
	Action            string  `json:"action"`
	Substitution      string  `json:"substitution"`
	Name              string  `json:"name"`
}

type ResponseObject struct {
	Content          *string `json:"content"`
	Response         string  `json:"response"`
	CacheCondition   string  `json:"cache_condition"`
	ContentType      string  `json:"content_type"`
	Status           string  `json:"status"`
	RequestCondition string  `json:"request_condition"`
	Name             string  `json:"name"`
}

type RequestSetting struct {
	ForceSSL string `json:"force_ssl"`
}
