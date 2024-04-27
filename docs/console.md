# Simple console command

You can check VCL behavior without VCL file in repl of falco console.

## Usage

```
falco console -h
=========================================================
    ____        __
   / __/______ / /_____ ____
  / /_ / __  // //  __// __ \
 / __// /_/ // // /__ / /_/ /
/_/   \____//_/ \___/ \____/  Fastly VCL developer tool

=========================================================
Usage:
    falco console [flags]

Flags:
    -s, --scope : Define initial scope
    -h, --help  : Show this help

Run console with fetch scope example:
    falco console -s fetch
```

[screenshot]

## Control Commands

In console, some control commands that start with `\` are enabled.

| Command            | Desctiption                                                  |
|:------------------:|:-------------------------------------------------------------|
| \s, \scope [scope] | Change input evaluation scope (recv, fetch, deliver, etc...) |
| \h, \help          | Show this help                                               |
| \q, \quit          | Quit console                                                 |

## Console Behavior

The console does single-line code evaluatation and must be valid of VCL syntax.
And some predefined variables depends on the scope, then you can change artibrary scope by typing the `\s` command:

```shell
@RECV>> \s FETCH
```

Now you can switch to the `fetch` scope.

## Evaluation

falco evaluates input as `statement` and `expression`, it means you cannot declare `backend`, `subroutine` - of root declarations. 
By inputting `set` statement, falco can store the value in this session. Of course `declare local var.XXX` statement also available.

If you want to see the variable value, type variable as expression:

```shell
@RECV>> set req.http.Foo = "bar";
@RECV>> req.http.Foo;
(STRING)bar
```

Falco evaluates expression and display value with its type.

Note that console runtime uses interpreter, therefore the result depends on the intepreter implementation.

