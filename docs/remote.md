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

Prefetch [VCL Snippets](https://docs.fastly.com/en/guides/about-vcl-snippets) from Fastly and parse as `VCL`.
falco support both of regular snippets and dynamic snippets, and could lint each scope snippets and `none` snippets that include manually.


#### Root inclusion example

You can use VCL Snippets in root of Custom VCL:

```
include "snippet::example_snippet";
```

#### Include in block statement

You can include VCL Snippets in some of block statements (e.g sburoutine, if block, etc):

```
sub vcl_recv {
  ...
  include "snippet::example_snippet";
  ...
}
```

#### Fastly boilerplate macro extraction

For example, if you create VCL Snippets and set type to `recv`, falco will extract it in place that boilerplate macro found:

```

sub vcl_recv {
  #FASTLY RECV  <= falco find this and extract VCL Snippets here
  ...
}
```

### Access Control Lists

Prefetch [Access Control Lists](https://docs.fastly.com/en/guides/about-acls) from Fastly and parse as `Acl`.

If you defined Access Control Lists named `my_acl`, falco deals with as acl:

```
acl my_acl {
  "ip_range01",
  "ip_range02",
  ...
}
```
