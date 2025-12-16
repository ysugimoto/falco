<p align="center">
<img src="https://user-images.githubusercontent.com/1000401/225396918-6490ea38-6883-434a-ac1f-e8b6188ec58b.png" width="320" />
</p>
<p align="center"><a href="https://www.fastly.com">Fastly</a> VCL developer tool</p>

----

[![Go Reference](https://pkg.go.dev/badge/github.com/ysugimoto/falco.svg)](https://pkg.go.dev/github.com/ysugimoto/falco)
![Build](https://github.com/ysugimoto/falco/actions/workflows/build.yml/badge.svg)


## Disclaimer

This is a VCL parser, but dedicated to Fastly's VCL (version 2.x), so we don't care about the latest Varnish (7.x or later) syntax.
The Varnish may have additional syntax, builtin function, predefined variables, but this tool may not parse correctly.

Additionally, Fastly provides its special builtin function, predefined variables. It's not compatible with Varnish.
But this tool is optimized for them, we could parse and lint/execute their declarations.

## Motivation

Fastly is a really fantastic CDN, but sometimes we have problems with deployment operations.
On deploy custom VCL to the Fastly, VCLs are validated when activating a new service version.
Typically our deployment flow using custom VCLs is following:

1. Clone active service and create new version
2. Delete existing custom VCLs
3. Upload new VCL files to the Fastly
4. Activate new device version **<= Validate VCLs on the Fastly cloud**

Above flows take a time, and then if we have some mistakes on VCL e.g. missing semicolon X(, the deployment will fail.
Additionally, unnecessary service versions will be created by our trivial issue.

To solve them, we made a Fastly dedicated tool to develop custom VCLs locally.

## Installation

Download binary from [releases page](https://github.com/ysugimoto/falco/releases) according to your platform and place it under the `$PATH`, or you can install via [Homebrew](https://brew.sh/):

```shell
$ brew install falco
```

You can compile this project by yourself with:

```shell
go install github.com/ysugimoto/falco/cmd/falco@latest
```

## Usage

Command help displays following:

```shell
falco -h
=========================================================
    ____        __
   / __/______ / /_____ ____
  / /_ / __  // //  __// __ \
 / __// /_/ // // /__ / /_/ /
/_/   \____//_/ \___/ \____/  Fastly VCL developer tool

=========================================================
Usage:
    falco [subcommand] [flags] [main vcl file]

Subcommands:
    lint      : Run lint (default)
    terraform : Run lint from terraform planned JSON
    stats     : Analyze VCL statistics
    simulate  : Run simulator server with provided VCLs
    test      : Run local testing for provided VCLs
    console   : Run terminal console
    fmt       : Run formatter for provided VCLs

See subcommands help with:
    falco [subcommand] -h

Common Flags:
    -I, --include_path : Add include path
    -h, --help         : Show this help
    -r, --remote       : Connect with Fastly API
    -V, --version      : Display build version
    -v                 : Output lint warnings (verbose)
    -vv                : Output all lint results (very verbose)
    -json              : Output results as JSON (very verbose)

Simple linting example:
    falco -I . -vv /path/to/vcl/main.vcl
```

`falco` provides some useful features for developing Fastly VCL.

## Linter

The main feature, parse and run lint your VCL locally, and report problems.
`falco` bundles many linter rules that come from the author's operation experience, Fastly recommends,
that you improve your VCL more robustly by passing the linter.

See [linter documentation](https://github.com/ysugimoto/falco/blob/main/docs/linter.md) in detail.

## Formatter

Format provided VCL by our recommended styles.
Currently we have a few options to control formatting style like [biomejs](https://github.com/biomejs/biome).
Through the formatter, your VCL codes have unified format even multiple people are maintaining VCL.

See [formatter documentation](./docs/formatter.md) in detail.

## Local Simulator / VCL Debugger

`falco` has self-implemented interpreter for running VCL program locally.
You can simulate how your VCL behaves through the simulator.

In addition to local simulator, `falco ` also provided VCL debugger.
You can debug your VCL step-by-step with dumping variables.

See [simulator documentation](https://github.com/ysugimoto/falco/blob/main/docs/simulator.md) in detail.

## VCL Unit Testing

You can run unit testing through the `falco` runtime.
The unit testing file also can be written in VCL, and run test for each subroutine that you want individually.

See [testing documentation](https://github.com/ysugimoto/falco/blob/main/docs/testing.md) in detail.

## Console

Falco supports simple terminal console to evaluate line input.
You can confirm behavior without actual VCL file.

See [console documentation](./docs/console.md) in detail.

## Terraform Support

`falco` supports to run features for [terraform](https://www.terraform.io/) planned result of [Fastly Provider](https://github.com/fastly/terraform-provider-fastly).

See [terraform.md](https://github.com/ysugimoto/falco/blob/main/docs/terraform.md) in detail.

## GitHub Actions Support

To integrate `falco` into your GitHub Actions pipeline, e.g. for linting:

    - name: Lint VCL
      uses: ain/falco-github-action@v1
      with:
        subcommand: lint
        options: "-v -I test/vcl/includes"
        target: test/vcl/file_to_be_linted.vcl

See [ain/falco-github-action](https://github.com/ain/falco-github-action) for documentation.

## Contribution

- Fork this repository
- Customize / Fix problem
- Send PR :-)
- Or feel free to create issues for us. We'll look into it

## License

MIT License

## Contributors

- [@ysugimoto](https://github.com/ysugimoto)
- [@smaeda-ks](https://github.com/smaeda-ks)
- [@shadialtarsha](https://github.com/shadialtarsha)
- [@davinci26](https://github.com/davinci26)
- [@ivomurrell](https://github.com/ivomurrell)
- [@MasonM](https://github.com/MasonM)
- [@richardmarshall](https://github.com/richardmarshall)
- [@jedisct1](https://github.com/jedisct1)

## Credits / Thanks

Logo created by [@studiomohawk](https://github.com/studiomohawk)
