package terraform

// Terraform planned input struct
// This struct could be unmarshled from input of `terraform show -json [planned json]
type Vcl struct {
	Content string `json:"content"`
	Main    bool   `json:"main"`
	Name    string `json:"name"`
}

type AclEntry struct {
	Comment string
	Ip      string
	Negated bool
	Subnet  string
}

type Acl struct {
	Name    string `json:"name"`
	Entries []*AclEntry
}

type DictionaryItem struct {
	Key   string
	Value string
}

type Dictionary struct {
	Name      string `json:"name"`
	WriteOnly bool   `json:"write_only"`
	Items     []*DictionaryItem
}

type Snippet struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	Priority int64  `json:"priority"`
}

type LoggingEndpoint struct {
	Name string `json:"name"`
}

// TODO(davinci26): We can unmarshall all the properties from the TF file
// and lint them to make sure they have sane values.
type Backend struct {
	Name    string  `json:"name"`
	Shield  *string `json:"shield"`
	Address *string `json:"address"`
}

type Director struct {
	Type     int      `json:"type"`
	Name     string   `json:"name"`
	Backends []string `json:"backends"`
	Retries  *int     `json:"retries"`
	Quorum   *int     `json:"quorum"`
}

type Condition struct {
	Name      string `json:"name"`
	Priority  int64  `json:"priority"`
	Statement string `json:"statement"`
	Type      string `json:"type"`
}

type Header struct {
	Action            string `json:"action"`
	CacheCondition    string `json:"cache_condition"`
	IgnoreIfSet       bool   `json:"ignore_if_set"`
	Name              string `json:"name"`
	Priority          int64  `json:"priority"`
	Regex             string `json:"regex"`
	RequestCondition  string `json:"request_condition"`
	ResponseCondition string `json:"response_condition"`
	Source            string `json:"source"`
	Destination       string `json:"destination"`
	Substitution      string `json:"substitution"`
	Type              string `json:"type"`
}

type ResponseObject struct {
	Name             string `json:"name"`
	ContentType      string `json:"content_type"`
	Content          string `json:"content"`
	Status           int64  `json:"status"`
	Response         string `json:"response"`
	RequestCondition string `json:"request_condition"`
	CacheCondition   string `json:"cache_condition"`
}

type FastlyResources struct {
	Services        map[string]*FastlyService
	AclEntries      []*fastlyAclEntryValues
	DictionaryItems []*fastlyDictionaryItems
}

type FastlyService struct {
	Name             string
	Vcls             []*Vcl
	Backends         []*Backend
	Acls             []*Acl
	Dictionaries     []*Dictionary
	Directors        []*Director
	Snippets         []*Snippet
	Conditions       []*Condition
	Headers          []*Header
	ResponseObjects  []*ResponseObject
	LoggingEndpoints []string
}

type fastlyServiceValues struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Vcl             []*Vcl            `json:"vcl"`
	Acl             []*Acl            `json:"acl"`
	Backend         []*Backend        `json:"backend"`
	Director        []*Director       `json:"director"`
	Dictionary      []*Dictionary     `json:"dictionary"`
	Snippets        []*Snippet        `json:"snippet"`
	Conditions      []*Condition      `json:"condition"`
	Headers         []*Header         `json:"header"`
	ResponseObjects []*ResponseObject `json:"response_object"`

	// Various kinds of realtime logging endpoints
	LoggingBigQuerty     []*LoggingEndpoint `json:"logging_bigqeury"`
	LoggingBlobStorage   []*LoggingEndpoint `json:"logging_blobstorage"`
	LoggingCloudFiles    []*LoggingEndpoint `json:"logging_cloudfiles"`
	LoggingDatadog       []*LoggingEndpoint `json:"logging_datadog"`
	LoggingDigitalOpean  []*LoggingEndpoint `json:"logging_digitalocean"`
	LoggingElasticsearch []*LoggingEndpoint `json:"logging_elasticsearch"`
	LoggingFtp           []*LoggingEndpoint `json:"logging_ftp"`
	LoggingGcs           []*LoggingEndpoint `json:"logging_gcs"`
	LoggingGooglePubSub  []*LoggingEndpoint `json:"logging_googlepubsub"`
	LoggingHeroku        []*LoggingEndpoint `json:"logging_heroku"`
	LoggingHttps         []*LoggingEndpoint `json:"logging_https"`
	LoggingKafka         []*LoggingEndpoint `json:"logging_kafka"`
	LoggingKinesis       []*LoggingEndpoint `json:"logging_kinesis"`
	LoggingLogEntries    []*LoggingEndpoint `json:"logging_logentries"`
	LoggingLoggly        []*LoggingEndpoint `json:"logging_loggly"`
	LoggingLogShuttle    []*LoggingEndpoint `json:"logging_logshuttle"`
	LoggingNewRelic      []*LoggingEndpoint `json:"logging_newrelic"`
	LoggingOpenStack     []*LoggingEndpoint `json:"logging_openstack"`
	LoggingPaperTrail    []*LoggingEndpoint `json:"logging_papertrail"`
	LoggingS3            []*LoggingEndpoint `json:"logging_s3"`
	LoggingScalyr        []*LoggingEndpoint `json:"logging_scalyr"`
	LoggingSftp          []*LoggingEndpoint `json:"logging_sftp"`
	LoggingSplunk        []*LoggingEndpoint `json:"logging_splunk"`
	LoggingSumoLogic     []*LoggingEndpoint `json:"logging_sumologic"`
	LoggingSyslog        []*LoggingEndpoint `json:"logging_syslog"`
}

type fastlyAclEntryValues struct {
	ServiceId string `json:"service_id"`
	Index     string
	Entries   []struct {
		Comment string `json:"comment"`
		Ip      string `json:"ip"`
		Negated bool   `json:"negated"`
		Subnet  string `json:"subnet"`
	} `json:"entry"`
}

type fastlyDictionaryItems struct {
	ServiceId string `json:"service_id"`
	Index     string
	Items     map[string]string `json:"items"`
}
