package config

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/ysugimoto/twist"
)

const (
	configurationFile = ".falco.yaml"
)

type Config struct {
	// Root configurations
	IncludePaths   []string `cli:"I,include_path" yaml:"include_paths"`
	Transforms     []string `cli:"t,transformer" yaml:"transformers"`
	Help           bool     `cli:"h,help"`
	VerboseLevel   string   `yaml:"verbose"`
	VerboseWarning bool     `cli:"v"`
	VerboseInfo    bool     `cli:"vv"`
	Version        bool     `cli:"V"`
	Remote         bool     `cli:"r,remote" yaml:"remote"`
	Json           bool     `cli:"json"`

	// Remote options, only provided via environment variable
	FastlyServiceID string `env:"FASTLY_SERVICE_ID"`
	FastlyApiKey    string `env:"FASTLY_API_KEY"`

	// Only can define in configuration file
	Rules LinterRules `yaml:"rules"`

	// CLI subcommands
	Commands Commands
}

// Adding type alias in order to implement some methods
type LinterRules map[string]string

func New(args []string) (*Config, error) {
	var options []twist.Option
	if file, err := findConfigFile(); err != nil {
		return nil, errors.WithStack(err)
	} else if file != "" {
		options = append(options, twist.WithYaml(file))
	}

	// finally, cascade config file -> environment -> cli option order
	options = append(options, twist.WithEnv(), twist.WithCli(args))

	c := &Config{}
	if err := twist.Mix(c, options...); err != nil {
		return nil, errors.WithStack(err)
	}
	c.Commands = parseCommands(args)

	// Merge verbose level
	switch c.VerboseLevel {
	case "warning":
		c.VerboseWarning = true
	case "info":
		c.VerboseInfo = true
	}

	return c, nil
}

func findConfigFile() (string, error) {
	// find up configuration file
	cwd, err := os.Getwd()
	if err != nil {
		return "", errors.WithStack(err)
	}

	for {
		file := filepath.Join(cwd, configurationFile)
		if _, err := os.Stat(file); err == nil {
			return file, nil
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
