# falco

falco is VCL parser and linter optimized for [Fastly](https://www.fastly.com).

![falco-demo](https://user-images.githubusercontent.com/1000401/124563760-4aab0e00-de7b-11eb-911b-a68aaa909802.gif)

## Disclaimer

This is a VCL parser, but dedicate to Fastly's VCL (version 2.x), so we don't care about latest Varnish (7.x or later) syntax.
The Varnish may have additional syntax, builtin function, predefined variables, but this tool may not parse correctly.

Additionally, Fastly provides its special builtin functio, predefined variables. It's not compatibility for Varnish.
But this is tool is optimized for them, we could parse and lint their declarations.

## Motivation

Fastly is really fantastic CDN, but sometimes we have problem for deployment operation.
On deploy custom VCL's to the Fastly, VCLs are validated when activate new service version.
Typically our deployment flow using custom VCLs is following:

1. Clone active service and create new version
2. Delete existing custom VCLs
3. Upload new VCL files to the Fastly
4. Activate new sevice version // <= Validate VCLs on the Fastly cloud

Above flows take a few times, and then if we have some mistakes on VCL e.g. missing semicolon X(, the deployment will fail.
Additionally, unnecessary service version will be created by our trivial issue.

To solve them, we made Fastly dedicated VCL parser and linter tool to notice syntax error and unexpected mistakes before starting above deployment flow.

## Installation

Donwload binary from [releaes page](https://github.com/ysugimoto/falco/releases) according your platform and place under the `$PATH`.

## Usage

Command help displays following:

```shell
falco -h
=======================================
  falco: Fastly VCL parser / linter
=======================================
Usage:
    falco [main vcl file]

Flags:
    -I, --include_path : Add include path
    -t, --transformer  : Specify transformer
    -h, --help         : Show this help
    -v,                : Verbose warning lint result
    -vv,               : Varbose all lint result

Example:
    falco -I . -vv /path/to/vcl/main.vcl
```

### Note:
Youe VCL will have dependent modules and loaded via `include [module]`. `falco` accept include path from `-I, --include_path` flag and search and load destination module from include path.

## Lint error

`falco` has builtin lint rules. see [rules](https://github.com/ysugimoto/falco/blob/main/docs/rules.md) in detail.

## Error Levels

`falco` reports three of severity on linting:

### ERROR

VCL may cause error on Fastly, or may cause unexpected behavior for acrual works.

### WRANING

VCL could work, but may have potencial bug and cause unexpected behavior for acrual works.

`falco` does not output warnings defaulty. To see them, run with `-v` option.

### INFORMATION

VCL is fine, but we suggest to improve your VCL considing from Fastly recommendation.

`falco` does not output informations defaulty. To see them, run with `-vv` option.

## Tranforming

`falco` is planning to transpile Fastly VCL to the other programing language e.g Go (HTTP service), node.js (Lambda@Edge) to use temporal CDN instead of Fastly.

## Contribution

- Fork this repository
- Customize / Fix problem
- Send PR :-)
- Or feel free to create issue for us. We'll look into it

## License

MIT License

## Author

Yoshiaki Sugimoto <sugimoto@wnotes.net>

