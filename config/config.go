package config

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/ysugimoto/twist"
)

var (
	configurationFiles = []string{".falco.yaml", ".falco.yml"}
)

// Formatting value constants
const (
	IndentStyleSpace  = "space"
	IndentStyleTab    = "tab"
	CommentStyleNone  = "none"
	CommentStyleSlash = "slash"
	CommentStyleSharp = "sharp"
)

type OverrideBackend struct {
	Host      string `yaml:"host"`
	SSL       bool   `yaml:"ssl" default:"true"`
	Unhealthy bool   `yaml:"unhealthy" default:"false"`
}

// Linter configuration
type LinterConfig struct {
	VerboseLevel            string              `yaml:"verbose"`
	VerboseWarning          bool                `cli:"v"`
	VerboseInfo             bool                `cli:"vv"`
	Rules                   map[string]string   `yaml:"rules"`
	EnforceSubroutineScopes map[string][]string `yaml:"enforce_subroutine_scopes"`
	IgnoreSubroutines       []string            `yaml:"ignore_subroutines"`
}

// Simulator configuration
type SimulatorConfig struct {
	Port         int      `cli:"p,port" yaml:"port" default:"3124"`
	IsDebug      bool     `cli:"debug"` // Enable only in CLI option
	IncludePaths []string // Copy from root field

	// HTTPS related configuration. If both fields are spcified, simulator will serve with HTTPS
	KeyFile  string `cli:"key" yaml:"key_file"`
	CertFile string `cli:"cert" yaml:"cert_file"`

	// Override Request configuration
	OverrideRequest *RequestConfig
}

// Testing configuration
type TestConfig struct {
	Timeout      int      `cli:"t,timeout" yaml:"timeout"`
	Filter       string   `cli:"f,filter" default:"*.test.vcl"`
	IncludePaths []string // Copy from root field
	OverrideHost string   `yaml:"host"`

	// Override Request configuration
	OverrideRequest *RequestConfig
}

// Console configuration
type ConsoleConfig struct {
	// Initial scope string, for example, recv, pass, fetch, etc...
	Scope string `cli:"scope" default:"recv"`

	// Override Request configuration
	OverrideRequest *RequestConfig
}

// Format configuration
type FormatConfig struct {
	// CLI options
	Overwrite bool `cli:"w,write" default:"false"`

	// Formatter options
	IndentWidth                int    `yaml:"indent_width" default:"2"`
	TrailingCommentWidth       int    `yaml:"trailing_comment_width" default:"2"`
	IndentStyle                string `yaml:"indent_style" default:"space"`
	LineWidth                  int    `yaml:"line_width" default:"120"`
	ExplicitStringConat        bool   `yaml:"explicit_string_concat" default:"false"`
	SortDeclarationProperty    bool   `yaml:"sort_declaration_property" default:"false"`
	AlignDeclarationProperty   bool   `yaml:"align_declaration_property" default:"false"`
	ElseIf                     bool   `yaml:"else_if" default:"false"`
	AlwaysNextLineElseIf       bool   `yaml:"always_next_line_else_if" default:"false"`
	ReturnStatementParenthesis bool   `yaml:"return_statement_parenthesis" default:"true"`
	SortDeclaration            bool   `yaml:"sort_declaration" defaul:"false"`
	AlignTrailingComment       bool   `yaml:"align_trailing_comment" default:"false"`
	CommentStyle               string `yaml:"comment_style" default:"none"`
	ShouldUseUnset             bool   `yaml:"should_use_unset" default:"false"`
	IndentCaseLabels           bool   `yaml:"indent_case_labels" default:"false"`
}

type Config struct {
	// Root configurations
	IncludePaths []string `cli:"I,include_path" yaml:"include_paths"`
	Transforms   []string `cli:"t,transformer" yaml:"transformers"`
	Help         bool     `cli:"h,help"`
	Version      bool     `cli:"V"`
	Remote       bool     `cli:"r,remote" yaml:"remote"`
	Json         bool     `cli:"json"`
	Request      string   `cli:"request"`

	// Remote options, only provided via environment variable
	FastlyServiceID string `env:"FASTLY_SERVICE_ID"`
	FastlyApiKey    string `env:"FASTLY_API_KEY"`

	// CLI subcommands
	Commands Commands

	// Override Origin fetching URL
	OverrideBackends map[string]*OverrideBackend `yaml:"override_backends"`

	// Override resource limits
	OverrideMaxBackends int `cli:"max_backends" yaml:"max_backends"`
	OverrideMaxAcls     int `cli:"mac_acls" yaml:"max_acls"`

	// Linter configuration
	Linter *LinterConfig `yaml:"linter"`
	// Simulator configuration
	Simulator *SimulatorConfig `yaml:"simulator"`
	// Testing configuration
	Testing *TestConfig `yaml:"testing"`
	// Console configuration
	Console *ConsoleConfig `yaml:"console"`
	// Format configuration
	Format *FormatConfig `yaml:"format"`
}

func New(args []string) (*Config, error) {
	var options []twist.Option
	if file, err := findConfigFile(); err != nil {
		return nil, errors.WithStack(err)
	} else if file != "" {
		options = append(options, twist.WithYaml(file))
	}

	// finally, cascade config file -> environment -> cli option order
	options = append(options, twist.WithEnv(), twist.WithCli(args))

	c := &Config{
		OverrideBackends: make(map[string]*OverrideBackend),
	}
	if err := twist.Mix(c, options...); err != nil {
		return nil, errors.WithStack(err)
	}
	c.Commands = parseCommands(args)

	// Merge verbose level
	switch c.Linter.VerboseLevel {
	case "warning":
		c.Linter.VerboseWarning = true
	case "info":
		c.Linter.VerboseInfo = true
	}

	// Load request configuration if provided
	if c.Request != "" {
		if rc, err := LoadRequestConfig(c.Request); err == nil {
			c.Simulator.OverrideRequest = rc
			c.Testing.OverrideRequest = rc
		}
	}

	// Copy common fields
	c.Simulator.IncludePaths = c.IncludePaths
	c.Testing.IncludePaths = c.IncludePaths

	return c, nil
}

func findConfigFile() (string, error) {
	// find up configuration file
	cwd, err := os.Getwd()
	if err != nil {
		return "", errors.WithStack(err)
	}

	for {
		for _, f := range configurationFiles {
			file := filepath.Join(cwd, f)
			if _, err := os.Stat(file); err == nil {
				return file, nil
			}
		}

		cwd = filepath.Dir(cwd)
		if cwd == "/" {
			// find up to root directory, stop it
			// @FIXME: on windows?
			break
		}
	}

	// not found
	return "", nil
}
