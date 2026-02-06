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

`falco` determines the scope of user-defined subroutines using three methods, in order of priority:

1. **Explicit annotation** - `@scope` comment above the subroutine
2. **Name suffix** - subroutine name ending with `_recv`, `_fetch`, etc.
3. **Call graph inference** - automatically inferred from callers

### Call graph inference

`falco` automatically infers scope by analyzing the call graph. If your subroutine is called from a Fastly lifecycle subroutine (like `vcl_recv` or `vcl_miss`), it inherits that scope without needing annotations.

```vcl
sub add_cdn_header {
  set bereq.http.CDN = "Fastly";
}

sub vcl_miss {
  #FASTLY MISS
  call add_cdn_header;  // add_cdn_header is inferred as MISS scope
}
```

This works transitively through the call chain:

```vcl
sub helper_inner {
  set bereq.http.X-Helper = "inner";
}

sub helper_outer {
  call helper_inner;  // helper_inner inherits scope from helper_outer's callers
}

sub vcl_miss {
  #FASTLY MISS
  call helper_outer;  // Both helper_outer and helper_inner get MISS scope
}
```

If a subroutine is called from multiple scopes, it receives the union of all caller scopes:

```vcl
sub to_origin {
  set bereq.http.CDN = "Fastly";
}

sub vcl_miss {
  #FASTLY MISS
  call to_origin;
}

sub vcl_pass {
  #FASTLY PASS
  call to_origin;  // to_origin is inferred as MISS|PASS scope
}
```

Subroutines that are never called from any lifecycle subroutine will trigger a warning, as their scope cannot be determined.

### Subroutine name

Explicit scope declaration takes priority over inference. If the subroutine name has a suffix of `_[scope]`, falco lints within that scope regardless of where it's called from.

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
are declared as comma separated values.

Then, if you apply a hint of scope on annotation, `falco` also understands scope. There are two ways to define the scope annotation:
1. `@scope: <scope_name1>, <scope_name2>` this is the newest annotation method and it should be preferred over 2.
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

## VCL Snippets

`falco` can also lint VCL snippet files that contain only statements (without subroutine declarations). This is useful for linting Fastly VCL snippets that are injected into specific subroutines.

To lint a snippet file, add a `@scope` annotation at the top of the file to specify which subroutine scope the snippet will run in:

```vcl
# @scope: deliver
unset resp.http.Server;
unset resp.http.X-Powered-By;
```

If a snippet file is missing the `@scope` annotation, `falco` will report an error:

```
falco lint snippet.vcl
🔥 [ERROR] VCL snippet requires @scope annotation (e.g., # @scope: deliver) (snippet-scope-required)
```

The available scope values are the same as for subroutine annotations: `recv`, `hash`, `hit`, `miss`, `pass`, `fetch`, `error`, `deliver`, and `log`.

## Linter Plugin

You can provide custom linter rule by writing your plugin. See [Plugin](./plugin.md) documentation in detail.

## Fastly related features

Partially supports fetching Fastly managed VCL snippets. See [remote.md](https://github.com/ysugimoto/falco/blob/master/docs/remote.md) in detail.

## Lint error

`falco` has built in lint rules. see [rules](https://github.com/ysugimoto/falco/blob/main/docs/rules.md) in detail. `falco` may report lots of errors and warnings because falco lints with strict type checks, disallows implicit type conversions even VCL is fuzzy typed language.

## Ignoring errors

Fastly also accepts some syntax and function which comes from Varnish (e.g `map()` function) but falco reports error for it. Then, you can put leading/trailing comments for each statements, falco will ignore the error.

The comment syntax is similar to eslint, but very simplified.
Note that this feature only ignores linting error, the parser error will be reported.

### Next Line

Put `// falco-ignore-next-line` comment on the statement, ignoring errors for next statement.

```vcl
sub vcl_recv {
  # FASTLY RECV

  // falco-ignore-next-line
  set req.http.Example = some.undefined.variable;

  // You can disable specific rules only
  // falco-ignore-next-line function/arguments, function/argument-type
  set req.http.foo = std.itoa(req.http.bar) + std.itoa(0, 1, 2);
}
```

### Current statement

Put `// falco-ignore` comment on the trailing, ignoring errors for current statement.

```vcl
sub vcl_recv {
  # FASTLY RECV

  set req.http.Example = some.undefined.variable; // falco-ignore

  // You can disable specific rules only
  set req.http.foo = std.itoa(req.http.bar) + std.itoa(0, 1, 2); // falco-ignore function/arguments, function/argument-type
}
```

### Range ignoring

falco recognizes `// falco-ignore-start` and `// falco-ignore-end` comment, ignore the errors between this range.

```vcl
sub vcl_recv {
  # FASTLY RECV

  // falco-ignore-start
  set req.http.Example = some.undefined.variable;
  // falco-ignore-end

  // You can disable specific rules only
  // falco-ignore-start function/arguments, function/argument-type
  set req.http.foo = std.itoa(req.http.bar) + std.itoa(0, 1, 2);
  // falco-ignore-end function/arguments, function/argument-type

  // Note that falco-ignore-end without rule names specified re-enables all rules
  // falco-ignore-start function/arguments
  set req.http.foo = std.itoa(0, 1, 2);
  // falco-ignore-start function/argument-type
  set req.http.foo = std.itoa(req.http.bar);
  // falco-ignore-end
  // Now both function/arguments and function/argument-type are enabled again.
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
