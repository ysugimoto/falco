package config

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/twist"
)

const (
	fastlyToml = "fastly.toml"
)

type Commands []string

func (c Commands) At(n int) string {
	if n > len(c)-1 {
		return ""
	}
	return c[n]
}

func SubCommands(args []string) Commands {
	if args == nil {
		args = os.Args[1:]
	}

	var sc Commands
	for i := range args {
		if !strings.HasPrefix(args[i], "-") {
			sc = append(sc, args[i])
		}
	}
	return sc
}

func New(args []string) (*Config, error) {
	var c Config
	var options []twist.Option

	if args == nil {
		args = os.Args[1:]
	}

	cwd, err := os.Getwd()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if toml := findUpConfig(cwd); toml != "" {
		options = append(options, twist.WithToml(toml))
	}
	options = append(options, twist.WithEnv(), twist.WithCli(args))

	if err := twist.Mix(&c, options...); err != nil {
		return nil, errors.WithStack(err)
	}
	return &c, nil
}

func findUpConfig(cwd string) string {
	for {
		target := filepath.Join(cwd, fastlyToml)
		if _, err := os.Stat(target); err == nil {
			// found
			return target
		}
		cwd = filepath.Dir(cwd)
		if cwd == "/" {
			break
		}
	}
	return ""
}
