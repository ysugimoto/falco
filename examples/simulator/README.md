# Simulator example

This directory has VCL file that can locally.

## Local simulator

You can run local simulator as following command:

```shell
falco -I . local ./simulator.vcl
```

Then simulator server will start on `localhost:3124`, you can send some HTTP request via `curl` or browser,
then get JSON response that how simulator processed.

## Local debugger

`falco` also have debugger, so you can debug your VCL with step-by-step:

```shell
falco -I . local --debug ./simulator.vcl
```

Then the debugger UI will start.
