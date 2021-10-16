# Use Fastly managed snippets

`falco` aims to run locally, but probably vcl has dependency of Fastly managed VCL -- Edge Dictionary, VCL snippets --- and linter may cause error if these are not specified,

In order to use them, falco provides remote option which prefetch Fastly managed VCL and do parse and lint.

## Prefetching managed VCL

### Provide remote flag in CLI

By supplying `-r, --remote` flag in command, falco communicates to Fastly API and retrieve VCL snippets.

For example:

```shell
falco -r -v /path/to/example.vcl
```

### Environment variables

Fastly API requires `API key` to authenticate, and `Service ID` to distinguish service, therefore you need to specift these values in your environment variable.
The environment varialbe name is fixed:

| variable name     | usage |
|:------------------|:----  |
| FASTLY_SERVICE_ID | Service ID |
| FASTLY_API_KEY    | API Key, you can create via [Personal API Tokens](https://manage.fastly.com/account/personal/tokens) |

**Note: We recommend the Fastly API Key has `global:read` scope. falco only just call _read_ related API.**


### Edge Dictionary

Prefetch [Edge Dictionary](https://docs.fastly.com/en/guides/about-edge-dictionaries) from Fastly and parse as `Table`.
Note that Edge Dictionary always treats as `STRING` type in VCL:

If you defined Edge Dictionary named `my_dictionary`, falco deals with as table:

```
table my_dictionary STRING {
  "[item_key01": "[item_value01]",
  "[item_key02": "[item_value02]",
  ...
}
```

You can access `my_dictionary` table in your custom VCL.

### Logging

Currently not supported.

### VCL snippets

Prefetch [VCL dynamic snippets](https://docs.fastly.com/en/guides/using-dynamic-vcl-snippets) and [VCL regular snippets](https://docs.fastly.com/en/guides/using-regular-vcl-snippets) from Fastly and parse them to embed in your VCL:

- embed VCLs that correspond to `include` statement like `include "snippet::<snipppet_name>"
- Find Fastly's macro (e.g. `#FASTLY recv`) and embed VCLs that correspond type

### Access control lists

Currently not supported.
