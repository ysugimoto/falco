package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"path/filepath"

	"github.com/fatih/color"
	"github.com/kyokomi/emoji"
	"github.com/mattn/go-colorable"
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
)

type multiStringFlags []string

func (m *multiStringFlags) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func (m *multiStringFlags) String() string {
	return fmt.Sprintf("%v", *m)
}

type Config struct {
	Transforms   multiStringFlags
	IncludePaths multiStringFlags
	Help         bool
	V            bool
	VV           bool
	Version      bool
	Remote       bool
}

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
    falco [main vcl file]

Flags:
    -I, --include_path : Add include path
    -t, --transformer  : Specify transformer
    -h, --help         : Show this help
    -r, --remote       : Communicate with Fastly API
    -V, --version      : Display build version
    -v                 : Verbose warning lint result
    -vv                : Varbose all lint result

Example:
    falco -I . -vv /path/to/vcl/main.vcl
`

	fmt.Println(strings.TrimLeft(usage, "\n"))
	os.Exit(1)
}

func main() {
	c := &Config{}
	fs := flag.NewFlagSet("app", flag.ExitOnError)
	fs.Var(&c.IncludePaths, "I", "Add include paths (short)")
	fs.Var(&c.IncludePaths, "include_path", "Add include paths (long)")
	fs.Var(&c.Transforms, "t", "Add VCL transformer (short)")
	fs.Var(&c.Transforms, "transformer", "Add VCL transformer (long)")
	fs.BoolVar(&c.Help, "h", false, "Show Usage")
	fs.BoolVar(&c.Help, "help", false, "Show Usage")
	fs.BoolVar(&c.V, "v", false, "Verbose warning")
	fs.BoolVar(&c.VV, "vv", false, "Verbose info")
	fs.BoolVar(&c.Version, "V", false, "Print Version")
	fs.BoolVar(&c.Version, "version", false, "Print Version")
	fs.BoolVar(&c.Remote, "r", false, "Use Remote")
	fs.BoolVar(&c.Remote, "remote", false, "Use Remote")

	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			printUsage()
		}
		os.Exit(1)
	}

	if c.Help {
		printUsage()
	} else if c.Version {
		writeln(white, version)
		os.Exit(1)
	}

	mainVcl := fs.Arg(0)
	if mainVcl == "" {
		printUsage()
	} else if _, err := os.Stat(mainVcl); err != nil {
		if err == os.ErrNotExist {
			writeln(white, "Input file %s is not found", mainVcl)
		} else {
			writeln(red, "Unexpected stat error: %s", err.Error())
		}
		os.Exit(1)
	}

	vcl, err := filepath.Abs(mainVcl)
	if err != nil {
		writeln(red, "Failed to get absolute path: %s", err.Error())
		os.Exit(1)
	}

	runner, err := NewRunner(vcl, c)
	if err != nil {
		writeln(red, err.Error())
		os.Exit(1)
	}

	result, err := runner.Run()
	if err != nil {
		if err != ErrParser {
			writeln(red, err.Error())
		}
		os.Exit(1)
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
		os.Exit(1)
	}

	if err := runner.Transform(result.Vcls); err != nil {
		writeln(red, err.Error())
		os.Exit(1)
	}
}
