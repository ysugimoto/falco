package main

import (
	"fmt"
	"os"
	"strings"

	"encoding/json"

	"github.com/fatih/color"
	"github.com/kyokomi/emoji"
	"github.com/mattn/go-colorable"
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/resolver"
	"github.com/ysugimoto/falco/terraform"
)

var version string = ""

var (
	output  = colorable.NewColorableStderr()
	yellow  = color.New(color.FgYellow)
	white   = color.New(color.FgWhite)
	red     = color.New(color.FgRed)
	green   = color.New(color.FgGreen)
	cyan    = color.New(color.FgCyan)
	magenta = color.New(color.FgMagenta)

	ErrExit = errors.New("exit")
)

const (
	subcommandLint      = "lint"
	subcommandTerraform = "terraform"
	subcommandStat      = "stat"
)

func write(c *color.Color, format string, args ...interface{}) {
	c.Fprint(output, emoji.Sprintf(format, args...))
}

func writeln(c *color.Color, format string, args ...interface{}) {
	write(c, format+"\n", args...)
}

func printUsage() {
	usage := `
=======================================
  falco: Fastly VCL parser / linter
=======================================
Usage:
    falco [subcommand] [main vcl file]

Subcommands:
    terraform : Run lint from terraform planned JSON
    lint      : Run lint (default)
    stat      : Calculate statistic for input VCL

Flags:
    -I, --include_path : Add include path
    -t, --transformer  : Specify transformer
    -h, --help         : Show this help
    -r, --remote       : Communicate with Fastly API
    -V, --version      : Display build version
    -v                 : Verbose warning lint result
    -vv                : Varbose all lint result
    -json              : Output statistics as JSON

Simple Linting example:
    falco -I . -vv /path/to/vcl/main.vcl

Get statistics example:
    falco -I . stats /path/to/vcl/main.vcl

Linting with terraform:
    terraform plan -out planned.out
    terraform show -json planned.out | falco -vv terraform
`

	fmt.Println(strings.TrimLeft(usage, "\n"))
	os.Exit(1)
}

func main() {
	c, err := config.New(os.Args[1:])
	if err != nil {
		writeln(red, "Failed to initialize config: %s", err)
		os.Exit(1)
	}
	if c.Help {
		printUsage()
	} else if c.Version {
		writeln(white, version)
		os.Exit(1)
	}

	var fetcher Fetcher
	// falco could lint multiple services so resolver should be a slice
	var resolvers []resolver.Resolver
	switch c.Commands.At(0) {
	case subcommandTerraform:
		fastlyServices, err := ParseStdin()
		if err == nil {
			resolvers = resolver.NewTerraformResolver(fastlyServices)
			fetcher = terraform.NewTerraformFetcher(fastlyServices)
		}
	case subcommandLint, subcommandStat:
		// "lint" command provides single file of service, then resolvers size is always 1
		resolvers, err = resolver.NewFileResolvers(c.Commands.At(1), c.IncludePaths)
	default:
		// "lint" command provides single file of service, then resolvers size is always 1
		resolvers, err = resolver.NewFileResolvers(c.Commands.At(0), c.IncludePaths)
	}

	if err != nil {
		writeln(red, err.Error())
		os.Exit(1)
	}

	var shouldExit bool
	for _, v := range resolvers {
		if name := v.Name(); name != "" {
			writeln(white, `Lint service of "%s"`, name)
			writeln(white, strings.Repeat("=", 18+len(name)))
		}

		runner, err := NewRunner(c, fetcher)
		if err != nil {
			writeln(red, err.Error())
			os.Exit(1)
		}

		var exitErr error
		switch c.Commands.At(0) {
		case subcommandStat:
			exitErr = runStats(runner, v, c.Json)
		default:
			exitErr = runLint(runner, v)
		}

		if exitErr == ErrExit {
			shouldExit = true
		}
	}

	if shouldExit {
		os.Exit(1)
	}
}

func runLint(runner *Runner, rslv resolver.Resolver) error {
	result, err := runner.Run(rslv)
	if err != nil {
		if err != ErrParser {
			writeln(red, err.Error())
		}
		return ErrExit
	}

	write(red, ":fire:%d errors, ", result.Errors)
	write(yellow, ":exclamation:%d warnings, ", result.Warnings)
	writeln(cyan, ":speaker:%d infos.", result.Infos)

	// Display message corresponds to runner result
	if result.Errors == 0 {
		switch {
		case result.Warnings > 0:
			writeln(white, "VCL seems having some warnings, but it should be OK :thumbsup:")
			if runner.level < LevelWarning {
				writeln(white, "To see warning detail, run command with -v option.")
			}
		case result.Infos > 0:
			writeln(green, "VCL looks fine :sparkles: And we suggested some informations to vcl get more accuracy :thumbsup:")
			if runner.level < LevelInfo {
				writeln(white, "To see informations detail, run command with -vv option.")
			}
		default:
			writeln(green, "VCL looks very nice :sparkles:")
		}
	}

	// if lint error is not zero, stop process
	if result.Errors > 0 {
		if len(runner.transformers) > 0 {
			writeln(white, "Program aborted. Please fix lint errors before transforming.")
		}
		return ErrExit
	}

	if err := runner.Transform(result.Vcl); err != nil {
		writeln(red, err.Error())
		return ErrExit
	}
	return nil
}

func runStats(runner *Runner, rslv resolver.Resolver, printJson bool) error {
	stats, err := runner.Stats(rslv)
	if err != nil {
		if err != ErrParser {
			writeln(red, err.Error())
		}
		return ErrExit
	}

	if printJson {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(stats); err != nil {
			writeln(red, err.Error())
			os.Exit(1)
		}
		return ErrExit
	}

	printStats(strings.Repeat("=", 80))
	printStats("| %-76s |", "falco VCL statistics ")
	printStats(strings.Repeat("=", 80))
	printStats("| %-22s | %51s |", "Main VCL File", stats.Main)
	printStats(strings.Repeat("=", 80))
	printStats("| %-22s | %51d |", "Included Module Files", stats.Files-1)
	printStats(strings.Repeat("-", 80))
	printStats("| %-22s | %51d |", "Total VCL Lines", stats.Lines)
	printStats(strings.Repeat("-", 80))
	printStats("| %-22s | %51d |", "Subroutines", stats.Subroutines)
	printStats(strings.Repeat("-", 80))
	printStats("| %-22s | %51d |", "Backends", stats.Backends)
	printStats(strings.Repeat("-", 80))
	printStats("| %-22s | %51d |", "Tables", stats.Tables)
	printStats(strings.Repeat("-", 80))
	printStats("| %-22s | %51d |", "Access Control Lists", stats.Acls)
	printStats(strings.Repeat("-", 80))
	printStats("| %-22s | %51d |", "Directors", stats.Directors)
	printStats(strings.Repeat("-", 80))
	return nil
}

func printStats(format string, args ...interface{}) {
	fmt.Fprintf(os.Stdout, format+"\n", args...)
}
