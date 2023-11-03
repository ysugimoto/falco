package remote

import "time"

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
	Name                string        `json:"name"`
	Shield              *string       `json:"shield"`
	BetweenBytesTimeout time.Duration `json:"between_bytes_timeout"`
	ConnectTimeout      time.Duration `json:"connect_timeout"`
	FirstByteTimeout    time.Duration `json:"first_byte_timeout"`
	HealthCheck         *string       `json:"healthcheck"`
	Host                string        `json:"hostname"`
	MaxConnection       int64         `json:"max_conn"`
	Port                int64         `json:"port"`
	OverrideHost        *string       `json:"override_host"`
	SSL                 bool          `json:"use_ssl"`
	SSLCertHostname     *string       `json:"ssl_cert_hostname"`
	SSLCheckCert        bool          `json:"ssl_check_cert"`
	SSLSniHostname      *string       `json:"ssl_sni_hostname"`
	Probe               *Healthcheck
}

type Healthcheck struct {
	Initial          int64    `json:"initial"`
	ExpectedResponse int64    `json:"expected_response"`
	CheckInterval    int64    `json:"check_interval"`
	Headers          []string `json:"headers"`
	Host             string   `json:"host"`
	HttpVersion      string   `json:"http_version"`
	Method           string   `json:"method"`
	Name             string   `json:"name"`
	Path             string   `json:"path"`
	Threshold        int64    `json:"threshold"`
	Timeout          int64    `json:"timeout"`
	Window           int64    `json:"window"`
}

type DirectorType int8

const (
	Random DirectorType = iota + 1
	Hash
	Client
	Shield // shield director type is special type for Origin-Shielding on Faslty configuration
)

type Director struct {
	Name     string       `json:"name"`
	Type     DirectorType `json:"type"`
	Backends []string     `json:"backends"`
}

type VCLSnippet struct {
	Id       string  `json:"id"`
	Name     string  `json:"name"`
	Dynamic  string  `json:"dynamic"`
	Type     string  `json:"type"`
	Priority string  `json:"priority"`
	Content  *string `json:"content"`
}
