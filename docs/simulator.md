# Local Simulator

`falco` has a self-implemented VCL interpreter, so it enables you to simulate your VCLs like Fastly locally as long as you trust our interpreter.
You can start simulator as following:

```shell
falco local /path/to/your/default.vcl
```

Then local server starts on http://localhost:3124, you can send HTTP request via curl, browser, etc.
The server response is a JSON which indicates VCL process information, it includes:

- VCL subroutine flow, what subroutine has processed with request/response information
- Entire `log` statement output
- Restart count
- Determined backend
- Served by cached object or not
- Processing time

Paticularly VCL subroutine flow is useful for debugging.

## Important Notice

**falco's interpreter is just a `simulator`, so we could not be depicted Fastly's actual behavior.
There are many limitations which are described below.**


## Debug mode

`falco` also includes TUI debugger so that you can debug VCL with step execution.
You can run debugger with providing `-debug` option on simulator:

```
falco local -debug /path/to/your/default.vcl
```

### Start debugging

When falco runs simulator with debugger, falco finds `@debugger` leading annotation comment in your VCL.
If comment is found, stop execution on the statement, for example:

```vcl
sub vcl_recv {
  #FASTLY RECV

  // @debugger
  set req.backend = example; <- stop on this statement
  ...
}
```

And the the debugger TUI accepts function keys to step execution:

- `F7` : resume execution to the next annotation comment
- `F8` : step in
- `F9` : step over
- `F10`: step out

And you can type other keys to dump the variable in debugger shell.

<img width="1128" alt="Screen Shot 2023-08-29 at 9 58 16" src="https://github.com/ysugimoto/falco/assets/1000401/9be8cd4c-d726-41ef-832a-483ed03579ca">

## Simulator Limitations

The simulator has a lot of limitations, of course Fastly edge cloud behaivor is undocumented and local environment reason.
As long as we reproduce Varnish lifecycle which is described [here](https://developer.fastly.com/learning/vcl/using/), and guess and suspect the behaivor but some of variables are set as virtual value.

Limitations are following:

- Even adding `Fastly-Debug` header, debug header values are fake because  we could not know what DataCenter is choosed
- Origin-Shielding and clustering fetch related features are ingored
- Cache object is not stored persistently, only manages in-memory so process are killed, all cache objects are deleted
- `Stale-While-Revalidate` does not work
- Extracted VCL in Faslty boilerplate marco is different. Only extracts VCL snippets
- May not add some of Fastly specific request/response headers
- WAF does not work
- ESI will not work correctly
- Director choosing algorithm result may be different
- All of backends always treats healthy
- Lots of predefined variables and builtin functions returns empty or tentative value

Variables that return tentative or inaccurate value describe at [variables.md]().

Functions that return tentative value or unexpected bahavior describe at [functions.md]().

