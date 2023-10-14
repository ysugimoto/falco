package config

import (
	"strings"
)

type Commands []string

func (c Commands) At(n int) string {
	if n > len(c)-1 {
		return ""
	}
	return c[n]
}

var needValueOptions = map[string]struct{}{
	"-I":             {},
	"--include_path": {},
	"-t":             {},
	"--transformer":  {},
	"-f":             {},
	"--filter":       {},
}

func parseCommands(args []string) Commands {
	var commands Commands
	for i := 0; i < len(args); i++ {
		if _, ok := needValueOptions[args[i]]; ok {
			i++
			continue
		}
		if strings.HasPrefix(args[i], "-") {
			continue
		}
		commands = append(commands, args[i])
	}

	return commands
}
