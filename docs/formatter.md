# Formatting VCL

You can format VCL to get unified styled VCL.

## Usage

```
falco fmt -h
=========================================================
    ____        __
   / __/______ / /_____ ____
  / /_ / __  // //  __// __ \
 / __// /_/ // // /__ / /_/ /
/_/   \____//_/ \___/ \____/  Fastly VCL developer tool

=========================================================
Usage:
    falco fmt [flags] ...files

Flags:
    -h, --help         : Show this help
    -w, --write        : Overwrite format result

files argument accepts glob file patterns

Simple format example:
    falco fmt /path/to/vcl/main.vcl
```

Simply you can run formatter as following:

```shell
falco fmt /path/to/your/default.vcl
```

And `fmt` command accepts multiple source files including glob patterns like:

```shell
falco fmt /path/to/your/*.vcl /path/to/another/**/*.vcl
```

## Format rules

Formatting rules have default parameter which we recommend but you can override them with `format` section in configuration file.
See [configuration documentation](https://github.com/ysugimoto/falco/blob/develop/docs/configuration.md) in detail.

Supporting rules are described the following table and sections.

| Name (configuration field)  | Type   | Default | Description                                                                                    |
|:----------------------------|:------:|:-------:|------------------------------------------------------------------------------------------------|
| indent_width                | INT    | 2       | Specify indent width                                                                           |
| indent_style                | STRING | space   | Specify indent style character. Either `space(whitespace)` or `tab(\t)` is accepted            |
| trailing_comment_width      | INT    | 2       | Specify space size for trailing comment                                                        |
| line_width                  | INT    | 120     | Specify max characters for each line. The overflowed characters are displayed at the next line |
| explicit_string_concat      | BOOL   | true    | Explicitly write string concatenation operator `+` between expressions                         |
| sort_declaration_property   | BOOL   | false   | If true, sort declaration properties like table, backend and director alphabetically           |
| align_declaration_property  | BOOL   | false   | If true, align declaration properties like table, backend and director                         |
| else_if                     | BOOL   | false   | Coerce use `else if` keyword for another if statement                                          |
| always_next_line_else_if    | BOOL   | false   | If true, always `else if` and `else` keywords print to the next line                           |
| return_statement_parentheis | BOOL   | true    | Coerce surrounded return statement ident by parenthesis                                        |
| sort_declaration            | BOOL   | false   | Sort root declaration by specific order                                                        |
| align_trailing_comment      | BOOL   | false   | Align trailing comments                                                                        |
| comment_style               | STRING | none    | Coerce comment character. Either `sharp(#)` or `slash(/)` is accepted                          |
| should_use_unset            | BOOL   | false   | Replace `remove` statement into `unset` statement                                              |
| indent_case_labels          | BOOL   | false   | If true, add indent for each `case` statement in `switch`                                      |

---

### Indent Width

**default: 2**

Define the indent width by unit. the formatted statements/propertied will have indent by provided width with `Indent Style` character.

Before:

```vcl
sub vcl_recv {
set req.http.Foo = "bar";
}
```

Formatted (indent_width: 2):

```vcl
sub vcl_recv {
  set req.http.Foo = "bar";
}
```

---

### Indent Style

**default: space**

Define the indent style. `space` value will use whitespace `" "` character, or `tab` value will use tab `\t` character.
And this character is repeated by `Indent Width` times.

```vcl
sub vcl_recv {
set req.http.Foo = "bar";
}
```

Formatted (indent_style: space):

```vcl
sub vcl_recv {
  set req.http.Foo = "bar";
}
```

---

### Trailing Comment Width

**default: 2**

Define trailing comment space size.

```vcl
sub vcl_recv {
  set req.http.Foo = "bar";
}// trailing comment
```

Formatted (trailing_comment_width: 2):

```vcl
sub vcl_recv {
  set req.http.Foo = "bar";
}  // trailing comment
```

---

### Line Width

**default: 120**

Specify max characters for each line. The overflowed characters are printed at the next line with the same ident.

> [!NOTE]
> Inserting line-feed is judged for each expression. It means formatter does not split in the middle of a sentence.

You can prevent this formatting rule by providing `-1` value to this configuration.

```vcl
sub vcl_recv {
  set req.http.Foo = "lorem" req.http.Sep "ipsum" req.http.Sep "dolor" req.http.Sep "sit" req.http.Sep "amet,";
}
```

Formatted (line_width: 80):

```vcl
sub vcl_recv {
  set req.http.Foo = "lorem" req.http.Sep "ipsum" req.http.Sep "dolor"
                     req.http.Sep "sit" req.http.Sep "amet,";
}
```

If condition example:

```vcl
sub vcl_recv {
  if (req.http.Header1 == "1" && req.http.Header2 = "2" && req.http.Header3 == "3" && req.http.Header4 == "4") {
      req.http.OK = "1";
  }
}
```

Formatted (line_width: 80):

```vcl
sub vcl_recv {
  if (
    req.http.Header1 == "1" && req.http.Header2 == "2" &&
    req.http.Header3 == "3" && req.http.Header4 == "4"
  ) {
    set req.http.OK = "1";
  }
}
```

---

### Explicit String Concat

**default: true**

Print string concatenation character of `+` explicitly if true.

```vcl
sub vcl_recv {
  set req.http.Foo = "lorem" "ipsum" "dolor" "sit" "amet,";
}
```

Formatted (explicit_string_concat: true):

```vcl
sub vcl_recv {
  set req.http.Foo = "lorem" + "ipsum" + "dolor" + "sit" + "amet,";
}
```

---

### Sort Declaration Property

**default: false**

If true, declaration properties will be printed with alphabetically sorted.
This rule affects to `backend`, `director`, and `table` declarations.

```vcl
backend example {
  .connect_timeout = 1s;
  .dynamic = true;
  .port = "443";
  .host = "example.com";
  .first_byte_timeout = 30s;
  .max_connections = 500;
  .between_bytes_timeout = 30s;
  .ssl = true;
  .probe = {
    .request = "GET / HTTP/1.1" "Host: example.com" "Connection: close";
    .dummy = true;
  }
}
```

Formatted (sort_declaration_property: true):

```vcl
backend example {
  .between_bytes_timeout = 30s;
  .connect_timeout = 1s;
  .dynamic = true;
  .first_byte_timeout = 30s;
  .host = "example.com";
  .max_connections = 500;
  .port = "443";
  .ssl = true;
  .probe = {
    .dummy = true;
    .request = "GET / HTTP/1.1" "Host: example.com" "Connection: close";
  }
}
```

---

### Align Declaration Property

**default: false**

If true, declaration properties will be aligned for max field character length.
This rule affects to `backend`, `director`, and `table` declarations.

```vcl
backend example {
  .connect_timeout = 1s;
  .dynamic = true;
  .port = "443";
  .host = "example.com";
  .first_byte_timeout = 30s;
  .max_connections = 500;
  .between_bytes_timeout = 30s;
  .ssl = true;
  .probe = {
    .request = "GET / HTTP/1.1" "Host: example.com" "Connection: close";
    .dummy = true;
  }
}`,
```

Formatted (align_declaration_property: true):

```vcl
backend example {
  .connect_timeout       = 1s;
  .dynamic               = true;
  .port                  = "443";
  .host                  = "example.com";
  .first_byte_timeout    = 30s;
  .max_connections       = 500;
  .between_bytes_timeout = 30s;
  .ssl                   = true;
  .probe                 = {
    .request = "GET / HTTP/1.1" "Host: example.com" "Connection: close";
    .dummy   = true;
  }
}
```

---

### Else If

**default: false**

VCL accepts a little kind of another if statement keyword like `else if`,  `elseif`, and `elsif`, sometimes it's annoying to recognize.
If this rule set `true`, print these keywords as `else if`.

```vcl
sub vcl_recv {
  if (req.http.Foo) {
    req.http.Status = "1";
  } elseif (req.http.Bar) {
    req.http.Status = "2";
  } elsif (req.http.Baz) {
    req.http.Status = "3";
  }
}
```

Formatted (else_if: true):

```vcl
sub vcl_recv {
  if (req.http.Foo) {
    req.http.Status = "1";
  } else if (req.http.Bar) {
    req.http.Status = "2";
  } else if (req.http.Baz) {
    req.http.Status = "3";
  }
}
```

---

### Return Statement Parenthesis

**default: true**

If true, coerce the surrounding parenthesis state ident of `return` statement.

```vcl
sub vcl_recv {
  return lookup;
}
```

Formatted (return_statement_parenthesis: true):

```vcl
sub vcl_recv {
  return (lookup);
}
```

---

## Sort Declaration

**default: false**

If true, sort root declarations by VCL directive order:

1. import/include statements
2. ACL
3. Backend
4. Director
5. Table
6. vcl_recv
7. vcl_hash
8. vcl_hit
9. vcl_miss
10. vcl_pass
11. vcl_fetch
12. vcl_error
13. vcl_deliver
14. vcl_log
15. user-defined subroutines

```vcl
sub vcl_fetch {
  ...
}

sub vcl_deliver {
  ...
}

sub vcl_recv {
  ...
}
```

Formatted (sort_declaration: true):

```vcl
sub vcl_recv {
  ...
}

sub vcl_fetch {
  ...
}

sub vcl_deliver {
  ...
}
```

---

## Align Trailing Comment

**default: false**

If true, align the trailing comment for each statement/declaration line:

```vcl
sub vcl_recv {
  set req.http.X-Forwarded-Host = "example.com";  // request comes from example.com
  set req.backend = example_com;  // set backend
}
```

Formatted (align_trailing_comment: true):


```vcl
sub vcl_recv {
  set req.http.X-Forwarded-Host = "example.com";  // request comes from example.com
  set req.backend = example_com;                  // set backend
}
```

---

## Always Next Line ElseIf

**default: false**

If true, the `else if` and `else` statement prints to the next line.

```vcl
sub vcl_recv {
  if (req.http.Foo) {
    ...
  } else if (req.http.Bar) {
    ...
  } else {
    ...
  }
}
```

Formatted (always_next_line_else_if: true):

```vcl
sub vcl_recv {
  if (req.http.Foo) {
    ...
  }
  else if (req.http.Bar) {
    ...
  }
  else {
    ...
  }
}
```

---

## Comment Style

**default: none**

Define the comment style. `sharp` value will use `#` character, or `slash` value will use `/` character.
Note that the inline style comment `/* ... */` does not replace.

```vcl
// Some leading comment
sub vcl_recv {
}
```

Formatted (comment_style: sharp):

```vcl
## Some leading comment
sub vcl_recv {
}
```

---

## Should Use Unset

**default: false**

The `remove` statement is alias of `unset` statement, it can be replaced if this rule is true.

```vcl
sub vcl_recv {
  remove req.http.Foo;
}
```

Formatted (should_use_unset: true):

```vcl
sub vcl_recv {
  unset req.http.Foo;
}
```

---

## Indent Case Labels

By default format the placement of case labels at the same indentation level as the outer block.
This keeps code in the case blocks indented the same amount as they would be in an if-else-if chain.

**default: false**

```vcl
switch (req.http.foo) {
    case "bar":
      break;
  case "baz":
    break;
default:
  break;
}
```

Formatted (false):

```vcl
switch (req.http.foo) {
case "bar":
  break;
case "baz":
  break;
default:
  break;
}
```

Formatted (true):

```vcl
switch (req.http.foo) {
  case "bar":
    break;
  case "baz":
    break;
  default:
    break;
}
```
