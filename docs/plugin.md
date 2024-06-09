# Plugin system

`falco` provides plugin system by calling external CLI command.

## Custom Linter Execution

Sometimes you want to write your own linter rule, and then you can do it by implementing CLI command.

## Plugin Implementation

Your plugin needs to implement binary messaging protocol between stdin and stdout/stderr.
falco provided `plugin` package that can implement them so you can use it to make plugin.

Also, we have example plugin implementation [here](../examples/plugin/), this is custom linter rule that the `backend` name must have `F_` prefix.

```go
// main.go
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/plugin"
)

func main() {
	// Read from stdin and decode AST tree struct from main falco linter.
	// Note that this function needs generics, it specified type conversion of provided statement.
	// In this case, linting for *ast.BackendDeclaration object.
	req, err := plugin.ReadLinterRequest[*ast.BackendDeclaration](os.Stdin)
	if err != nil {
 		// If some error has occured, send back message to stderr
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// Prepare send back response message
	resp := &plugin.LinterResponse{}

	// Main linting logic, the backend name must have "F_" prefix
	// By using generics, req.Statement could be *ast.BackendDeclaration pointer.
	if !strings.HasPrefix(req.Statement.Name.Value, "F_") {
 		// Report ERROR severity in linter
		resp.Error(`Backend name must start with "F_"`)

		// Or, report WARNING severity in linter
		// resp.Warning(`Backend name must start with "F_"`)

 		// Or, report INFO severity in linter
		// resp.Info(`Backend name must start with "F_"`)
	}

	// Send back result message to stdout including some linting errors
	resp.Write(os.Stdout)
}
```

After that, you can build CLI binary with having `falco-` prefix:

```shell
go build -o falco-backend-name .
```

And put built binary in your `$PATH` as executable.

## Put instruction to call plugin in VCL

falco recognizes `@plugin` annotation to call plugin linter. To call above backend name linter, put leading comment on `backend` declaration.

```vcl
// @plugin: backend-name
backend example_com {
  .connect_timeout = 1s;
  .dynamic = true;
  .port = "443";
  .host = "httpbin.org";
  .first_byte_timeout = 20s;
  .max_connections = 500;
  .between_bytes_timeout = 20s;
  .share_key = "xei5lohleex3Joh5ie5uy7du";
  .ssl = true;
  .ssl_sni_hostname = "example.com";
  .ssl_cert_hostname = "example.com";
  .ssl_check_cert = always;
  .min_tls_version = "1.2";
  .max_tls_version = "1.2";
  .bypass_local_route_table = false;
  .probe = {
    .request = "GET / HTTP/1.1" "Host: example.com" "Connection: close";
    .dummy = true;
    .threshold = 1;
    .window = 2;
    .timeout = 5s;
    .initial = 1;
    .expected_response = 200;
    .interval = 10s;
  }
}

...(other declarations)
```

And then you can run custom plugin linter via falco linter. In this case, the backend nake does not have `F_` prefix so linter reports `ERROR` on linting results.

Additionally, you can put additional arguments to plugin:

```vcl
// @plugin: backend-name arg1 arg2 ...
```

And then you can receive these arguments via `(*plugin.LinterRequest).Arguments` as string slice:

```go
req, err := plugin.ReadLinterRequest[*ast.BackendDeclaration](os.Stdin)
fmt.Println(req.Arguments[0]) // arg1
fmt.Println(req.Arguments[2]) // arg2
```

This is useful for switch or control linting behavior in your plugin without implementing another plugin.

## Other Specs

1. To reduce binary message between falco linter and plugin, we enable custom linter for each *statement* only. You often want to access all declarations on your plugin, but it cannot do for now. Therefore if you want to do linting for all backends, you need to put annotation comment to all backend declarations.
2. From performance reason, we omit AST meta informations like filename, line number and position and all comments. Typically you don't need to read AST meta informations on linting but the falco main process displays plugin error with AST meta informations.
3. AST is read-only on the pluging. The plugin cannot modify AST tree.
4. You can everythin in your plugin. It means you can do network access, reading local file, etc... that as possible as the programming language can if you don't mind the linting performance.
