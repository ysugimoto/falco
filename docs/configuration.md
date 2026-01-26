# Configuration

On command start running, `falco` finds up `.falco.yml` file from the current directory.
If the file is found, load and set to CLI configuration.

## Configuration File Structure

Here is a full configuration file example:

```yaml
// .falco.yaml

## Basic configurations
include_paths: [".", "/path/to/include"] 
remote: true
max_backends: 5
max_acls: 1000

## Linter configurations
linter:
  verbose: warning
  rules:
    acl/syntax: error
  enforce_subroutine_scopes:
    fastly_managed_waf: [recv, pass]
  ignore_subroutines: [ignore_sub, custom_sub]

## Formatter configurations
format:
  indent_width: 2
  indent_style: space
  trailing_comment_width: 2                                                        |
  line_width: 120
  explicit_string_concat: false
  sort_declaration_property: false
  align_declaration_property: false
  else_if: false
  always_next_line_else_if:  false
  return_statement_parenthesis: false
  sort_declaration: false
  align_trailing_comment: false
  comment_style: none
  should_use_unset: false
  indent_case_labels: false

## Simulator configuration
simulator:
  port: 3124
  max_backends: 100
  max_acls: 100
  key_file: /path/to/key_file.pem
  cert_file: /path/to/cert_file.pem
  edge_dictionary:
    dict_name:
      key1: value1
      key2: value2

## Testing configuration
testing:
  timeout: 100
  host: example.com
  filter: *.test.vcl
  edge_dictionary:
    dict_name:
      key1: value1
      key2: value2
  overrides:
    client.as.name: Foobar

## Backend Overrides
override_backends:
  F_httpbin_org:
    host: example.com
    ssl: true
    unhealthy: true
```

falco cascades each setting from the order of `Default Setting` -> `Configuration File` -> `CLI Arguments` to override.
All configurations of configuration files and CLI arguments are described following table:

| Configuration Field                     | Type                | Default     | CLI Argument       | Description                                                                                                                           |
|:----------------------------------------|:-------------------:|:-----------:|:------------------:|:--------------------------------------------------------------------------------------------------------------------------------------|
| include_paths                           | Array<String>       | []          | -I, --include_path | Include VCL paths                                                                                                                     |
| remote                                  | Boolean             | false       | -r, --remote       | Fetch remote resources of Fastly                                                                                                      |
| max_backends                            | Integer             | 5           | --max_backends     | Override Fastly's backend amount limitation                                                                                           |
| max_acls                                | Integer             | 1000        | --max_acls         | Override Fastly's acl amount limitation                                                                                               |
| linter                                  | Object              | null        | -                  | Override linter rules                                                                                                                 |
| linter.verbose                          | String              | error       | -v, -vv            | Verbose level, `warning` or `info` is valid                                                                                           |
| linter.rules                            | Object              | null        | -                  | Override linter rules                                                                                                                 |
| linter.rules.[rule_name]                | String              | -           | -                  | Override linter error level for the rule name, see [rules](https://github.com/ysugimoto/falco/blob/develop/docs/rules.md)             |
| linter.enforce_subroutine_scopes        | Object              | null        | -                  | Coerce subroutine scope for specified list of subroutine names. will be useful for Fastly managed snippet that cannot be modified.   |
| linter.enforce_subroutine_scopes.[name] | Array<String>       | []          | -                  | `name` is subroutine name and specify acceptable scope as an array.                                                                   |
| linter.ignore_subroutines               | Array<String>       | []          | -                  | Ignore subroutine linting for specified list of subroutine names. will be useful for Fastly managed snippet that cannot be modified. |
| linter.generated                        | Boolean             | false       | --generated        | Lint VCL as **generated** VCL. generated means that VCL comes from `show VCL` data in Fastly management console.                      |
| simulator                               | Object              | null        | -                  | Simulator configuration object                                                                                                        |
| simulator.port                          | Integer             | 3124        | -p, --port         | Simulator server listen port                                                                                                          |
| simulator.key_file                      | String              | -           | --key              | TLS server key file path                                                                                                              |
| simulator.cert_file                     | String              | -           | --cert             | TLS server cert file path                                                                                                             |
| simulator.edge_dictionary               | Object              | null        | -                  | Local edge dictionary item definitions                                                                                                |
| simulator.edge_dictionary.[name]        | Map<String, String> | -           | -                  | Local edge dictionary name                                                                                                            |
| testing                                 | Object              | null        | -                  | Testing configuration object                                                                                                          |
| testing.timeout                         | Integer             | 10          | -t, --timeout      | Set timeout to stop testing                                                                                                           |
| testing.filter                          | String              | \*.test.vcl | -f, --filter       | Provide filter (glob) pattern to find the testing VCL files.                                                                          |
| testing.host                            | String              | -           | --host             | Provide virtual hostname to override the `req.http.Host` header value.                                                                |
| testing.watch                           | Boolean             | false       | -w, --watch        | If true, watch and run test when VCL files have changed.                                                                              |
| testing.edge_dictionary                 | Object              | null        | -                  | Local edge dictionary item definitions                                                                                                |
| testing.edge_dictionary.[name]          | Object              | -           | -                  | Local edge dictionary name                                                                                                            |
| testing.overrides                       | Map<String, String> | -           | -                  | Override predefined variable value                                                                                                    |
| override_backends                       | Object              | -           | -                  | Override backend settings in main VCL which correspond to the name. Key of backend name accepts glob pattern                          |
| override_backends                       | Object              | -           | -                  | Override backend settings in main VCL which correspond to the name. Key of backend name accepts glob pattern                          |
| override_backends.[name]                | Object              | -           | -                  | Backend name to override                                                                                                              |
| override_backends.[name].host           | String              | -           | -                  | Backend host to override                                                                                                              |
| override_backends.[name].ssl            | Boolean             | true        | -                  | Use HTTPS when set `true`                                                                                                             |
| override_backends.[name].unhealthy      | Boolean             | false       | -                  | Override backend to be unhealthy when set `true`                                                                                      |





