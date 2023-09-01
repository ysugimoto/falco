# Linter

## Usage

```
falco lint -h
=========================================================
    ____        __
   / __/______ / /_____ ____
  / /_ / __  // //  __// __ \
 / __// /_/ // // /__ / /_/ /
/_/   \____//_/ \___/ \____/  Fastly VCL developer tool

=========================================================
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
```

### Configuration

You can override default configurations via `.falco.yml` configuration file or cli arguments. See [configuration documentation](https://github.com/ysugimoto/falco/blob/develop/docs/configuration.md) in detail.


### Note

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

## Lint error

`falco` has built in lint rules. see [rules](https://github.com/ysugimoto/falco/blob/main/docs/rules.md) in detail. `falco` may report lots of errors and warnings because falco lints with strict type checks, disallows implicit type conversions even VCL is fuzzy typed language.

## Ignoring errors

Fastly also accepts some syntax and function which comes from Varnish (e.g `map()` function) but falco reports error for it. Then, you can put leading/trailing comemnts for each statements, falco will ignore the error.

The comment syntax is similar to eslint, but very simplified.
Note that this feature only ignores linting error, the parser erorr will be reported.

### Next Line

Put `// falco-ignore-next-line` comment on the statement, ignoring errors for next statement.

```vcl
sub vcl_recv {
  # FASTLY RECV

  // falco-ignore-next-line
  set req.http.Example = some.undefined.variable;
}
```

### Current statement

Put `// falco-ignore` comment on the trailing, ignoring errors for current statement.

```vcl
sub vcl_recv {
  # FASTLY RECV

  set req.http.Example = some.undefined.variable; // falco-ignore
}
```

### Range ignoring

falco recognizes `// falco-ignore-start` and `// falco-ignore-end` comment, ignore the errors between this range.

```vcl
sub vcl_recv {
  # FASTLY RECV

  // falco-ignore-start
  set req.http.Example = some.undefined.variable;
  // falco-igore-end

}
```

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
