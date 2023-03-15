<p align="center">
<img src="https://user-images.githubusercontent.com/1000401/225396918-6490ea38-6883-434a-ac1f-e8b6188ec58b.png" width="320" />
</p>
<p align="center">VCL parser and linter optimized for <a href="https://www.fastly.com">Fastly</a>.</p>

----

[![Go Reference](https://pkg.go.dev/badge/github.com/ysugimoto/falco.svg)](https://pkg.go.dev/github.com/ysugimoto/falco)
![Build](https://github.com/ysugimoto/falco/actions/workflows/build.yml/badge.svg)


## Disclaimer

This is a VCL parser, but dedicated to Fastly's VCL (version 2.x), so we don't care about the latest Varnish (7.x or later) syntax.
The Varnish may have additional syntax, builtin function, predefined variables, but this tool may not parse correctly.

Additionally, Fastly provides its special builtin function, predefined variables. It's not compatible with Varnish.
But this tool is optimized for them, we could parse and lint their declarations.

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

To solve them, we made a Fastly dedicated VCL parser and linter tool to notice syntax errors and unexpected mistakes before starting the deployment flow.

## Installation

Download binary from [releases page](https://github.com/ysugimoto/falco/releases) according to your platform and place it under the `$PATH`.

Or compile it yourself with `go install github.com/ysugimoto/falco/cmd/falco@latest`.

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
    -r, --remote       : Communicate with Fastly API
    -V, --version      : Display build version
    -v,                : Verbose warning lint result
    -vv,               : Verbose all lint result

Example:
    falco -I . -vv /path/to/vcl/main.vcl
```

### Note:
Your VCL will have dependent modules loaded via `include [module]`. `falco` accept include path from `-I, --include_path` flag and search and load destination module from include path.

## User defined subroutine

On linting, `falco` could not recognize when the user-defined subroutine is called, so you should apply the subroutine scope by adding annotation or its subroutine name. falco understands call scope by following rules:

### Subroutine name

If the subroutine name has a suffix of `_[scope]`, falco lint within that scope.

```vcl
sub custom_recv { // name has `_recv` suffix, lint with RECV scope
  ...
}

sub custom_fetch { // name has `_fetch` suffix, lint with FETCH scope
  ...
}
```

Following table describes subroutine name and recognizing scope:

| suffix  | scope   | example               |
|:--------|:--------|:----------------------|
| _recv    | RECV    | sub custom_recv {}    |
| _miss    | MISS    | sub custom_miss {}    |
| _hash    | HASH    | sub custom_hash {}    |
| _pass    | PASS    | sub custom_pass {}    |
| _fetch   | FETCH   | sub custom_fetch {}   |
| _error   | ERROR   | sub custom_error {}   |
| _deliver | DELIVER | sub custom_deliver {} |
| _log     | LOG     | sub custom_log {}     |

### Annotation

For some reasons, the subroutine name could not be changed. Or you want to use this function in multiple scopes. Multiple scopes
are declared as comma seperated values.

Then, if you apply a hint of scope on annotation, `falco` also understands scope. There are two ways to define the scope annotation:
1. `@scope: <scope_name1>, <scope_name2>` this is the newest annotation method and it should be prefered over 2.
2. `@<scope_name1>, <scope_name2>`, this is used to maintain backwards compatibility and it may be deprecated in the future.

```vcl
// @scope: recv, miss
sub custom_process {
   // subroutine has `recv` annotation, lint with RECV|MISS scope.
   // All variables must be accessible in both RECV and MISS scope.
  ...
}

// @fetch, miss
sub custom_request {
  // subroutine has `fetch` annotation, lint with FETCH scope
  ...
}
```

Following table describes annotation name and recognizing scope:

| annotation  | scope   | example                      |
|:------------|:--------|:-----------------------------|
| @recv       | RECV    | // @recv<br>sub custom {}    |
| @miss       | MISS    | // @miss<br>sub custom {}    |
| @hash       | HASH    | // @hash<br>sub custom {}    |
| @pass       | PASS    | // @pass<br>sub custom {}    |
| @fetch      | FETCH   | // @fetch<br>sub custom {}   |
| @error      | ERROR   | // @error<br>sub custom {}   |
| @deliver    | DELIVER | // @deliver<br>sub custom {} |
| @log        | LOG     | // @log<br>sub custom {}     |

## Fastly related features

Partially supports fetching Fastly managed VCL snippets. See [remote.md](https://github.com/ysugimoto/falco/blob/master/docs/remote.md) in detail.

## Terraform support

`falco` supports to parse and lint for [terraform](https://www.terraform.io/) planned result of [Fastly Provider](https://github.com/fastly/terraform-provider-fastly). See [terraform.md](https://github.com/ysugimoto/falco/blob/master/docs/terraform.md) in detail.

## Lint error

`falco` has built in lint rules. see [rules](https://github.com/ysugimoto/falco/blob/main/docs/rules.md) in detail. `falco` may report lots of errors and warnings because falco lints with strict type checks, disallows implicit type conversions even VCL is fuzzy typed language.

## Overriding Severity

To avoid them, you can override severity levels by putting a configuration file named `.falcorc` on working directory. the configuration file contents format is following:

```yaml
## /path/to/working/directory/.falcorc
regex/matched-value-override: IGNORE
...
```

Format is simply a yaml key-value object. The key is rule name, see [rules.md](https://github.com/ysugimoto/falco/blob/main/docs/rules.md) and value should be one of `IGNORE`, `INFO`, `WARNING` and `ERROR`, case insensitive.

In the above case, the rule of `regex/matched-value-override` reports `INFO` as default, but overrides `IGNORE` which does not report it.

## Error Levels

`falco` reports three of severity on linting:

### ERROR

VCL may cause errors on Fastly, or may cause unexpected behavior for actual works.

### WARNING

VCL could work, but may have potential bug and cause unexpected behavior for actual works.

`falco` does not output warnings as default. To see them, run with `-v` option.

### INFORMATION

VCL is fine, but we suggest you improve your VCL considering Fastly recommendation.

`falco` does not output information as default. To see them, run with `-vv` option.

## Transforming

`falco` is planning to transpile Fastly VCL to the other programming language e.g Go (HTTP service), node.js (Lambda@Edge) to use temporal CDN instead of Fastly.

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

## Credeits / Thanks

Logo created by [@studimohawk](https://github.com/studiomohawk)
