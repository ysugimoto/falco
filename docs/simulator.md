# Local Simulator

`falco` has a self-implemented VCL interpreter, so it enables you to simulate your VCLs like Fastly locally as long as you trust our interpreter.

## Usage

```
falco simulate -h
=========================================================
    ____        __
   / __/______ / /_____ ____
  / /_ / __  // //  __// __ \
 / __// /_/ // // /__ / /_/ /
/_/   \____//_/ \___/ \____/  Fastly VCL developer tool

=========================================================
Usage:
    falco simulate [flags]

Flags:
    -I, --include_path : Add include path
    -h, --help         : Show this help
    -r, --remote       : Connect with Fastly API
    --proxy            : Enable actual proxy behavior
    -request           : Simulate request config
    -debug             : Enable debug mode
    --max_backends     : Override max backends limitation
    --max_acls         : Override max acls limitation
    --key              : Specify TLS server key file
    --cert             : Specify TLS cert file

Local simulator example:
    falco simulate -I . /path/to/vcl/main.vcl

Local debugger example:
    falco simulate -I . -debug /path/to/vcl/main.vcl
```

### Configuration

You can override default configurations via `.falco.yml` configuration file or cli arguments. See [configuration documentation](https://github.com/ysugimoto/falco/blob/develop/docs/configuration.md) in detail.


You can start the simulator as follows:

```shell
falco simulate /path/to/your/default.vcl
```

Then simulator server starts on http://localhost:3124, you can send HTTP request via curl, browser, etc.
The server response is a JSON which indicates VCL process information, including the following information:

- VCL subroutine flow, what subroutine has processed with request/response information
- Entire `log` statement output
- Restart count
- Determined backend
- Served by a cached object or not
- Processing time
- Actual HTTP Response without body

Particularly VCL subroutine flow is useful for debugging.

## Important Notice

**falco's interpreter is just a `simulator`, so we could not be depicted Fastly's actual behavior.
There are many limitations which are described below.**

## TLS Server

Typically Fastly runs with TLS environment so your VCL may has HTTPS-related logic.
falco supports to run as HTTPS server with your key/cert files. We recommend to use [mkcert](https://github.com/FiloSottile/mkcert) to generate key/cert file on your local machine.

```shell
# Generate certificates for localhost
mkcert localhost

# Run as HTTP server
falco simulate /path/to/your/default.vcl --key /path/to/localhost-key.pem --cert /path/to/localhost.pem
```

Then falco serve with https://localhost:3124.

## Override Edge Dictionary Items

Edge Dictionary values are managed in Fastly cloud but often we have some logics that relates to its value (e.g flag true/false), and write-only dictionary items could access via remote API.
To simulate its behavior with specific value, falco supports overriding edge dictionary item locally from configuration.

See `simulator.edge_dictionary` field in [configuration.md](./configuration.md).

## Debug Mode

`falco` also includes TUI debugger so that you can debug VCL with step execution.
You can run the debugger by providing `-debug` option on the simulator:

```
falco local -debug /path/to/your/default.vcl
```

## Actual Proxy Behavior

In default, falco simulator responds process flow JSON for a HTTP request on http://localhost:3124 - protocol and port may be changed - but falco also can respond actual HTTP proxy response (e.g origin or edge response), it's useful for E2E testing via example HTTP request.

To be enable the actual HTTP proxy, provide `--proxy` option to `simulator` subcommand:

```shell
falco simulate --proxy /path/to/your/default.vcl
```

### Start Debugging

When falco runs the simulator with the debugger, falco finds `@debugger` leading annotation comment in your VCL.
If the comment is found, stop execution on the statement, for example:

```vcl
sub vcl_recv {
  #FASTLY RECV

  // @debugger
  set req.backend = example; <- stop on this statement
  ...
}
```

And the debugger TUI accepts function keys to step execution:

- `F7` : resume execution to the next annotation comment
- `F8` : step in
- `F9` : step over
- `F10`: step out

You can type other keys to dump the variable in the debugger shell.

<img width="1128" alt="debugger example" src="https://github.com/ysugimoto/falco/assets/1000401/9be8cd4c-d726-41ef-832a-483ed03579ca">

### Debug Adapter Protocol support

`falco` supports [Debug Adapter Protocol](https://microsoft.github.io/debug-adapter-protocol/).
You can launch falco's debugger by calling `falco dap` subcommand from your editor.

> [!NOTE]
> Currently, `falco dap` doesn't support Fastly remote resources.

For Neovim with [nvim-dap](https://github.com/mfussenegger/nvim-dap), the configurations below can be used to launch debugging session.

```lua
local dap = require('dap')
dap.adapters.vcl = {
  name = 'falco',
  type = 'executable',
  command = 'falco',
  args = { 'dap' },
}
dap.configurations.vcl = {
  {
    type = 'vcl',
    request = 'launch',
    name = "Debug VCL by falco",
    mainVCL = "${file}",
    includePaths = { "${workspaceFolder}" },
  },
}
```

## Simulator Limitations

The simulator has a lot of limitations, of course, Fastly Edge Behaviors is undocumented and it comes from local environmental reasons.
As possible we can reproduce Varnish lifecycle which is described [here](https://developer.fastly.com/learning/vcl/using/), and guess and suspect the behavior but some of the variables are set tentative values.

Limitations are the following:

- Even adding `Fastly-Debug` header, debug header values are fake because we do not know what DataCenter is chosen
- Origin-Shielding and clustering, fetch-related features are unsupported
- Cache object is not stored persistently, only managed in-memory, so when the process is killed, all cache objects are deleted
- `Stale-While-Revalidate` does not work
- Extracted VCL in Faslty boilerplate marco is different. Only extracts VCL snippets
- May not add some of Fastly specific request/response headers
- WAF does not work
- ESI will not work correctly
- Director choosing algorithm result may be different
- All backends always treat healthy (but explicitly be unavailable from configuration)
- Could not look at private edge dictionary item due to Fastly API not responding to its item
- Lots of predefined variables and builtin functions return empty or tentative value

Variables that return tentative or inaccurate values are described at [variables.md](https://github.com/ysugimoto/falco/blob/develop/docs/variables.md).
Functions that return tentative value or unexpected behavior are described at [functions.md](https://github.com/ysugimoto/falco/blob/develop/docs/functions.md).

