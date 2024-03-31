package main

import (
	"strings"
)

func printHelp(cmd string) {
	printSplash()
	switch cmd {
	case subcommandTerraform:
		printTerraformHelp()
	case subcommandSimulate:
		printSimulateHelp()
	case subcommandStats:
		printStatsHelp()
	case subcommandTest:
		printTestHelp()
	case subcommandLint:
		printLintHelp()
	default:
		printGlobalHelp()
	}
}

func printSplash() {
	writeln(white, strings.TrimSpace(`
=========================================================
    ____        __
   / __/______ / /_____ ____ 
  / /_ / __ `+` // //  __// __ \
 / __// /_/ // // /__ / /_/ /
/_/   \____//_/ \___/ \____/  Fastly VCL developer tool

=========================================================
	`))
}

func printGlobalHelp() {
	writeln(white, strings.TrimSpace(`
Usage:
    falco [subcommand] [flags] [main vcl file]

Subcommands:
    lint      : Run lint (default)
    terraform : Run lint from terraform planned JSON
    stats     : Analyze VCL statistics
    simulate  : Run simulator server with provided VCLs
    test      : Run local testing for provided VCLs

See subcommands help with:
    falco [subcommand] -h

All Flags:
    -I, --include_path : Add include path
    -h, --help         : Show this help
    -r, --remote       : Connect with Fastly API
    -V, --version      : Display build version
    -v                 : Output lint warnings (verbose)
    -vv                : Output all lint results (very verbose)
    -json              : Output results as JSON (very verbose)

Simple linting example:
    falco -I . -vv /path/to/vcl/main.vcl
	`))
}

func printTerraformHelp() {
	writeln(white, strings.TrimSpace(`
Usage:
    falco terraform [action] [flags]

Actions:
    lint     : Run lint (default)
    stats    : Analyze VCL statistics
    simulate : Run simulator server with planned JSON
    test     : Run local testing for planned JSON

Flags:
    -I, --include_path : Add include path
    -h, --help         : Show this help
    -v                 : Output lint warnings (verbose)
    -vv                : Output all lint results (very verbose)
    -json              : Output results as JSON (very verbose)

Linting with terraform:
    terraform plan -out planned.out
    terraform show -json planned.out | falco -vv terraform
	`))
}

func printSimulateHelp() {
	writeln(white, strings.TrimSpace(`
Usage:
    falco simulate [flags]

Flags:
    -I, --include_path : Add include path
    -h, --help         : Show this help
    -r, --remote       : Connect with Fastly API
    -request           : Simulate request config
    -body              : Output response body
    -debug             : Enable debug mode
    --max_backends     : Override max backends limitation
    --max_acls         : Override max acls limitation

Local simulator example:
    falco simulate -I . /path/to/vcl/main.vcl

Local debugger example:
    falco simulate -I . -debug /path/to/vcl/main.vcl
	`))
}

func printStatsHelp() {
	writeln(white, strings.TrimSpace(`
Usage:
    falco stats [flags]

Flags:
    -I, --include_path : Add include path
    -h, --help         : Show this help
    -r, --remote       : Connect with Fastly API
    -json              : Output results as JSON

Get statistics example:
    falco stats -I . /path/to/vcl/main.vcl
	`))
}

func printTestHelp() {
	writeln(white, strings.TrimSpace(`
Usage:
    falco test [flags]

Flags:
    -I, --include_path : Add include path
    -h, --help         : Show this help
    -r, --remote       : Connect with Fastly API
    -t, --timeout      : Set timeout to running test
    -f, --filter       : Override glob filter to find test files
    -json              : Output results as JSON
    -request           : Override request config
    --max_backends     : Override max backends limitation
    --max_acls         : Override max acls limitation

Local testing example:
    falco test -I . -I ./tests /path/to/vcl/main.vcl
	`))
}

func printLintHelp() {
	writeln(white, strings.TrimSpace(`
Usage:
    falco lint [flags]

Flags:
    -I, --include_path : Add include path
    -h, --help         : Show this help
    -r, --remote       : Connect with Fastly API
    -V, --version      : Display build version
    -v                 : Output lint warnings (verbose)
    -vv                : Output all lint results (very verbose)
    -json              : Output results as JSON (very verbose)

Simple linting with very verbose example:
    falco lint -I . -vv /path/to/vcl/main.vcl
	`))
}
