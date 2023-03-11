package config

// Config struct respects fastly.toml that is used for Compute@Edge configuration.
// But we extends its structure, linter and simulator fields that configuration for falco behavior
// and drop "setup" field because it does not need for working locally
// see: https://developer.fastly.com/reference/compute/fastly-toml/
type Config struct {
	ManifestVersion int         `toml:"manifest_version" default:"2"` // no use in falco
	ServiceId       string      `toml:"service_id" env:"FASTLY_SERVICE_ID"`
	LocalServer     LocalServer `toml:"local_server"`
	Scripts         Scripts     `toml:"scripts"`

	// falco extended fields
	Falco FalcoConfig `toml:"falco"`
}

type FalcoConfig struct {
	Version      bool      `cli:"v,version"`
	Linter       Linter    `toml:"linter"`
	Simulator    Simulator `toml:"simulator"`
	Stats        Stats     `toml:"stats"`
	ApiKey       string    `env:"FASTLY_API_KEY"`
	Help         bool      `cli:"h,help"`
	IncludePaths []string  `toml:"include_paths" cli:"I,include_path"`
	EnableRemote bool      `toml:"remote"`
}

type LocalServer struct {
	Backends     map[string]Backend    `toml:"backends"`
	Dictionaries map[string]Dictionary `toml:"dictionaries"`
}

type Backend struct {
	Description  string `toml:"description"`
	Url          string `toml:"url"`
	OverrideHost string `toml:"override_host"`
	CertHost     string `toml:"cert_host"`
	UseSni       bool   `toml:"use_sni"`
}

type DictionaryFormat string

const (
	DictionaryFormatJson       = "json"
	DictionaryFormatInlineToml = "inline-toml"
)

type Dictionary struct {
	Contents map[string]string `toml:"contents"`
	File     string            `toml:"file"`
	Format   DictionaryFormat  `toml:"format"`
}

type Scripts struct {
	Build     string `toml:"build"`
	PostBuild string `toml:"post_build"` // no use in falco
}

// falco only
type VerboseLevel string

const (
	VerboseLevelDefault = "error"
	VerboseLevelInfo    = "info"
	VerboseLevelWarning = "warning"
)

// falco only
type Linter struct {
	Verbose VerboseLevel      `toml:"verbose"`
	Info    bool              `cli:"vv"`
	Warning bool              `cli:"v"`
	Rules   map[string]string `toml:"rules_override"`
}

// falco only
type Simulator struct {
	Debug      bool   `toml:"debug" env:"FALCO_DEBUG"`
	ServerPort string `toml:"server_port" defaut:"3124"`
}

// falco only
type Stats struct {
	OutputJSON bool `toml:"json" cli:"j,json"`
}
