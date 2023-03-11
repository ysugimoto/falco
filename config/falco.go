package config

// Falco specific configurations.
// User can specify following fields in fastly.toml:
//
// fastly.toml
//
// ...original configurations
//
// [falco]
//   watch = true
//   include_paths = [".", "/path/to/modules"]
//
//   [falco.linter]
//     [falco.linter.rules]
//       "some/rule" = "ERROR"
//
//   [falco.stats]
//     json = true
//
//   [falco.simulator]
//     debug = true
//     server_port = 3124
//

// falco only
type FalcoConfig struct {
	Version      bool      `cli:"v,version"`
	Linter       Linter    `toml:"linter"`
	Simulator    Simulator `toml:"simulator"`
	Stats        Stats     `toml:"stats"`
	ApiKey       string    `env:"FASTLY_API_KEY"`
	Help         bool      `cli:"h,help"`
	IncludePaths []string  `toml:"include_paths" cli:"I,include_path"`
	EnableRemote bool      `toml:"fetch_remote_resources"`
	Watch        bool      `toml:"watch" cli:"w,watch"`
}

// falco only
type Linter struct {
	Info    bool              `cli:"vv"`
	Warning bool              `cli:"v"`
	Rules   map[string]string `toml:"rule_overrides"`
}

// falco only
type Simulator struct {
	Debug      bool `toml:"debug" env:"FALCO_DEBUG"`
	ServerPort int  `toml:"server_port" defaut:"3124"`
}

// falco only
type Stats struct {
	OutputJSON bool `toml:"json" cli:"j,json"`
}
