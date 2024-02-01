# Linter rules

This file describes `falco` linter rules and how to fix it.

## acl/syntax

Syntax error on ACL definition.

Acl syntax is:

```vcl
acl (?<acl_name>[a-zA-Z0-9_]+) {
  (?<inverse>!?)"(?<ip_address>[0-9a-z\.:]+)"(/?)(?<cidr_mask>[0-9]+);
  ...
}
```

For example:

```vcl
acl internal {
  "10.0.0.1";
  !"10.0.0.2";
  "10.0.0.3"/32;
  !"10.0.0.4"/32;
  ...
}
```

Note: `ip_address` variable could specify ipv6 format like "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff".

Fastly Document : https://developer.fastly.com/reference/vcl/declarations/acl/


## acl/duplicated

Duplicate ACL declaration.

Problem:
```vcl
acl internal {
  ...
}

acl internal { // Duplicated
  ...
}
```

Fix:
```vcl
acl internal {
  ...
}
```

## backend/syntax

Syntax error on BACKEND definition.

Backend syntax is:

```vcl
backend (?<backend_name>[a-zA-Z0-9_]+) {
  // common property
  .(?<property_name>[a-zA-Z0-9_]+) = (?<property_value>.+);
  ...

  // probe object (for healthcheck)
  .probe = {
    .(?<property_name>[a-zA-Z0-9_]+) = (?<property_value>.+);
    ...
  }
}
```

For example:

```vcl
backend example_backend {
  .host = "example.com";

  .probe = {
    .request = "GET / HTTP/1.1" "Host: example.com" "Connection: close";
  }
}
```

Fastly Document: https://developer.fastly.com/reference/vcl/declarations/backend/

## backend/duplicated

Duplicate BACKEND declaration.

Problem:

```vcl
backend example {
  ...
}

backend example { // Duplicated
  ...
}
```

Fix:

```vcl
backend example {
  ...
}
```

## backend/notfound

Backend is not found in director or `req.backend`.

Problem:

```vcl
sub vcl_recv {
  ...
  set req.backend = F_example_backend_0; // F_example_backend_0 is not found
}
```

Fix:

```vcl
backend F_example_backend_0 {
  ...
}

...

sub vcl_recv {
  ...
  set req.backend = F_example_backend_0;
}
```

## backend/prober-configuration

Misconfiguration for backend probe section.
The `.initial` property should be less than `.threshold` property.

Problem:

```vcl
backend F_example_backend_0 {
  ...
  .probe = {
      .initial   = 5;
      .threshold = 2;
  }
}
```

Fix:

```vcl
backend F_example_backend_0 {
  ...
  .probe = {
      .initial   = 5;
      .threshold = 10;
  }
}
```

## director/syntax

Syntax error on DIRECTOR definition.

Director syntax is:

```vcl
director (?<director_name>[a-zA-Z0-9_]+) (?<directory_type>random|fallback|hash|client|chash) {
  // common property
  .(?<property_name>[a-zA-Z0-9_]+) = (?<property_value>.+);
  ...

  // backend object
  { .(?<property_name>[a-zA-Z0-9_]+) = (?<property_value>.+); ... }
  ...
}
```

For example:

```vcl
director example_director client {
  .quorum = "50%";
  { .backend= F_origin_0; .weight = 1; }
}
```

Fastly document: https://developer.fastly.com/reference/vcl/declarations/director/

## director/duplicated

Duplicate DIRECTOR declaration.

Problem:

```vcl
director example fallback {
  ...
}

director example fallback { // Duplicated
  ...
}
```

Fix:

```vcl
director example fallback {
  ...
}
```

## director/props-random

Required property is not declared on `random` director.

Fastly document: https://developer.fastly.com/reference/vcl/declarations/director/#random

## director/props-fallback

Required property is not declared on `fallback` director.

Fastly document: https://developer.fastly.com/reference/vcl/declarations/director/#fallback

## director/props-hash

Required property is not declared on `hash` director.

Fastly document: https://developer.fastly.com/reference/vcl/declarations/director/#content

## director/props-client

Required property is not declared on `client` director.

Fastly document: https://developer.fastly.com/reference/vcl/declarations/director/#client

## director/props-chash

Required property is not declared on `chash` director.

Fastly document: https://developer.fastly.com/reference/vcl/declarations/director/#consistent-hashing

## director/backend-required

Director must have one backend at least.

Problem:

```vcl
director example client {
  .quorum = "50%";

  // Nothing to specify backend
}
```

Fix:

```vcl
director example client {
  .quorum = "50%";

  { .backend = F_origin_0; .weight = 1; }
}
```

## table/syntax

Syntax error on TABLE declaration.

Table syntax is:

```vcl
table (?<table_name>[a-zA-Z0-9_]+) (?<value_type>(STRING|INTEGER|BOOL|FLOAT|BACKEND|ACL|RTIME)?) {
  "(?<property_name>.+)" = (?<property_value>.+),
  ...
}
```

For example:

```vcl
table example_table {
  "some_key": "value",
}
```

Note: `value_type` is optional and default is `STRING`.

Fastly document: https://developer.fastly.com/reference/vcl/declarations/table/

## table/type-variation

Invalid `value_type` spefication on TABLE. `value_type` is allowed to specify with `STRING`, `INTEGER`, `BOOL`, `FLOAT`, `BACKEND`, `ACL` and `RTIME`.

Problem:

```vcl
table example_table FOO { // unexpected value type of FOO
  "some_key": "value",
  ...
}
```

Fix:

```vcl
table example_table {
  "some_key": "value",
  ...
}
```

Note: The COMMA of last table property can omit.

Fastly document: https://developer.fastly.com/reference/vcl/declarations/table/#type-variations

## table/item-limitation

Table properties is limited under 1000 items.

Problem:

```vcl
table example_table {
  "some_key": "value",
  ...(1000 items) // limited under 1000 items
}
```

Fix:

```vcl
table example_table {
  "some_key": "value",
  ...(under 999 items)
}
```

Note: 1000 items as default, but you may increase this limitation by contacting to Fastly support.

Fastly document: https://developer.fastly.com/reference/vcl/declarations/table/#limitations

## table/duplicated

Duplicate TABLE declaration.

Problem:

```vcl
table example {
  ...
}

table example { // Duplicated
  ...
}
```

Fix:

```vcl
table example {
  ...
}
```

## subroutine/syntax

Syntax error on Subroutine declaration.

Subroutine syntax is:

```vcl
sub (?<subroutine_name>[a-zA-Z0-9_]+) {
  ...statements
}
```

For example:

```vcl
sub vcl_recv {
  set req.backend = F_origin_0;
}
```

Fastly document: https://developer.fastly.com/reference/vcl/subroutines/

## subroutine/boilerplate-macro

Fastly wants boilerplate macro on reserved subroutine.

Problem:
```vcl
sub vcl_recv {
  ...statements
}
```

Fix:

```vcl
sub vcl_recv {
  #Fastly recv

  set req.backend = F_origin_0;
}
```


Fastly document: https://developer.fastly.com/learning/vcl/using/#adding-vcl-to-your-service-configuration

## subroutine/duplicated

Duplicate Subroutine declaration.

Problem:

```vcl
sub check_password {
  ...
}

sub check_password { // Duplicated
  ...
}
```

Fix:

```vcl
sub check_password {
  ...
}
```

## subroutine/invalid-return-type

A functional subroutine declaration has an invalid return type, or return type is specified for state-machine subroutine like `vcl_recv`.

Problem:

```vcl
sub functional_subroutine COMPLEX { // COMPLEX type is invalid
    ....
}
```

Fix:

```vcl
sub functional_subroutine STRING {
    ....
}
```

## penaltybox/syntax

Syntax error on `penaltybox` declaration.

Declaration syntax is:

```vcl
penaltybox (?<penaltybox_name>[a-zA-Z0-9_]+) {}
```

Fastly document: https://developer.fastly.com/reference/vcl/declarations/penaltybox/

## penaltybox/nonempty-block

The `penaltybox` declaration block content must be empty.

Declaration syntax is:

```vcl
penaltybox (?<penaltybox_name>[a-zA-Z0-9_]+) {
  // Must be empty
}
```

Fastly document: https://developer.fastly.com/reference/vcl/declarations/penaltybox/

## penaltybox/duplicated

The `penaltybox` declaration is duplicated.


Problem:

```vcl
penaltybox foo {}
penaltybox foo {}
```

Fix:

```vcl
penaltybox foo {}
```

## ratecounter/syntax

Syntax error on `ratecounter` declaration.

Declaration syntax is:

```vcl
ratecounter (?<ratecounter_name>[a-zA-Z0-9_]+) {}
```

Fastly document: https://developer.fastly.com/reference/vcl/declarations/ratecounter/

## ratecounter/nonempty-block

The `ratecounter` declaration block content must be empty.

Declaration syntax is:

```vcl
ratecounter (?<ratecounter_name>[a-zA-Z0-9_]+) {
  // Must be empty
}
```

Fastly document: https://developer.fastly.com/reference/vcl/declarations/ratecounter/

## ratecounter/duplicated

The `ratecounter` declaration is duplicated.


Problem:

```vcl
ratecounter foo {}
ratecounter foo {}
```

Fix:

```vcl
ratecounter foo {}
```

## declare-statement/syntax

Syntax error on `declare` statement.

Statement syntax is:

```vcl
declare local (?<variable_name>var\.[a-zA-Z0-9_]+) (?<variable_type>(STRING|INTEGER|BOOL|FLOAT|BACKEND|ACL|RTIME)>;
```

For example:

```vcl
declare local var.exampleString STRING;
```

Fastly document: https://developer.fastly.com/reference/vcl/variables/#user-defined-variables

## declare-statement/invalid-type

declare variable type is invalid.

Problem:
```vcl
declare local var.Example FOO; // variable type is invalid
```

Fix:
```vcl
declare local var.Example STRING;
```

Fastly document: https://developer.fastly.com/reference/vcl/variables/#user-defined-variables

## declare-statement/duplicated

Duplicate declare variable statement.

Problem:
```vcl
declare local var.Example STRING;
declare local var.Example INTEGER; // var.Example is already declared.
```

Fix:
```vcl
declare local var.Example STRING;
```

## set-statement/syntax

Syntax error on `set` statement.

set syntax is:

```vcl
set (?<identifier>[a-zA-Z0-9\._-:]+) (?<operator>(\+|\*|\/|%|\||&|\^|<<|>>|rol|ror|&&|\|\|)?=) (?<expression>.+);
```

For example:

```vcl
set req.http.X-Forwarded-For = client.ip;
set req.http.Cookie:session = "session";
```

Fastly document: https://developer.fastly.com/reference/vcl/statements/set/

## operator/assignment

In VCL, bang operator could not use in set/add statement expression, and only string concatenation expression could use.

```vcl
declare local var.Foo BOOL;
declare local var.Bar STRING;
set var.Bar = "foo" "bar";                      // -> valid, string concatenation operator can use
set var.Foo = !false;                           // -> invalid, could not use in set statement
set var.Foo = req.http.Host == "example.com";   // -> invalid, equal operator could not use in set statement
set var.Foo = (req.http.Host == "example.com"); // -> valid, equal operator cau use inside grouped expression set statement
```

Fastly document: https://developer.fastly.com/reference/vcl/operators/#assignment-operators

## unset-statement/syntax

Syntax error on `unset` statement.

unset syntax is:

```vcl
unset (?<identifier>[a-zA-Z0-9\._-:]+);
```

For example:

```vcl
unset req.http.X-Forwarded-For;
```

Fastly document: https://developer.fastly.com/reference/vcl/statements/unset/

## remove-statement/syntax

Syntax error on `remove` statement.

remove syntax is:

```vcl
remove (?<identifier>[a-zA-Z0-9\._-:]+);
```

For example:

```vcl
remove req.http.X-Forwarded-For;
```

Note: `remove` is just alias for `unset`.

Faslty document: https://developer.fastly.com/reference/vcl/statements/remove/

## operator/conditional

Conditional operator is using for unexpected type.

Problem:
```vcl
if (beresp.status ~ "200") { // beresp.status is INTEGER, regex operator cannot use for INTEGER type.
  ...
}
```

Fix:
```vcl
if (beresp.status == 200) {
  ...
}
```

Faslty document: https://developer.fastly.com/reference/vcl/operators/#conditional-operators

## restart-statement/scope

Calling `restart` on invalid scope, the `restart` statement enables in `RECV`, `HIT`, `FETCH`, `ERROR` and `DELIVER` scope.

Problem:
```vcl
sub vcl_hash {
  #Fastly hash
  restart; // restart cannot use in HASH scope.
}
```

Fastly document: https://developer.fastly.com/reference/vcl/statements/restart

## add-statement/syntax

Syntax error on `add` statement.

add syntax is:

```vcl
add (?<identifier>[a-zA-Z0-9\._-:]+) = (?<expression>.+);
```

For example:

```vcl
add req.http.Cookie = "additional_cookie;
}
```

Note: may only `=` operator can use in `add` statement operator.

Fastly document: https://developer.fastly.com/reference/vcl/statements/add/

## call-statement/syntax

Syntax error on `call` statement.

call syntax is:

```vcl
call (?<identifier>[a-zA-Z0-9\._]+);
```

For example:

```vcl
call check_password;
```

Fastly document: https://developer.fastly.com/reference/vcl/statements/call/

## call-statement/subroutine-notfound

Calling subroutine must be defined before this statement.

Problem:
```vcl
sub vcl_recv {
  call auth; // calling "auth" subroutine before it is defined
}

sub auth {
  ...
}
```

Fix:

```vcl
sub auth {
  ...
}

sub vcl_recv {
  call auth;
}
```

## error-statement/scope

Calling `error` on invalid scope, the `error` statement could use in `RECV`, `HIT`, `MISS`, `PASS` and `FETCH`.

Problem:
```vcl
sub vcl_deliver {
  #Fastly deliver
  error 699; // error cannot use in DELIVER scope.
}
```

Fastly document: https://developer.fastly.com/reference/vcl/statements/error/

## error-statement/code

Faslty recommends error statement code should use in range of 600-699.

Problem:
```vcl
sub vcl_recv {
  #Fastly recv

  ...
  error 799; // custom error code should use in range of 600-699
}
```

Fix:
```vcl
sub vcl_recv {
  #Fastly recv

  ...
  error 699; // custom error code should use in range of 600-699
}
```
Fastly document: https://developer.fastly.com/reference/vcl/statements/error/#best-practices-for-using-status-codes-for-errors

## synthetic-statement/scope

Calling `synthetic` on invalid scope, the `synthetic` statement could use only in `ERROR`.

Problem:
```vcl
sub vcl_deliver {
  #Fastly deliver
  synthetic {"some of error"} // synthetic cannot use in DELIVER scope.
}
```

Fastly document: https://developer.fastly.com/reference/vcl/statements/synthetic/

## synthetic-base64-statement/scope

Calling `synthetic.base64` on invalid scope, the `synthetic.base64` statement could use only in `ERROR`.

Problem:
```vcl
sub vcl_deliver {
  #Fastly deliver
  synthetic.base64 {"some of error"} // synthetic.base64 cannot use in DELIVER scope.
}
```

Fastly document: https://developer.fastly.com/reference/vcl/statements/synthetic-base64/

## condition/literal

`if` condtion expression accepts STRING or BOOL (evaluate as truthy/falsy), but forbid to use literal.

For example:

```vcl
if (req.http.Host) { ... }                  // -> valid, req.http.Host is STRING and used as identity
if ("foobar") { ... }                       // -> invalid, string literal in condition expression could not use
if (req.http.Host == "example.com") { ... } // -> valid, left expression is identity
if ("example.com" == req.http.Host) { ... } // -> invalid(!), left expression is string literal... messy X(
  ```

## valid-ip

IP string is invalid.

Problem:
```vcl
declare local var.LocalIP IP;
set var.LocalIP = std.ip("192.168.0.1", "192.168.0.256"); // Invalid IP
```

## function/arguments

Calling function arguments count mismatch.

Problem:
```vcl
declare local var.LocalIP IP;
set var.LocalIP = std.ip("192.168.0.1"); // std.ip function expects 2 arguemnts but supply 1 argument
```

Fix:
```vcl
declare local var.LocalIP IP;
set var.LocalIP = std.ip("192.168.0.1", "192.168.0.2");
```

## function/argument-type

Calling function argument type mismatch.

Problem:
```vcl
declare local var.lat FLOAT;
set var.lat = math.floor("2.2"); // math.floor expects 1st argument as FLOAT but STRING supplied
```

Fix:
```vcl
declare local var.lat FLOAT;
set var.lat = math.floor(2.2);
```

## include/module-not-found

Include target module not found.

## include/module-load-failed

Failed to load include target module.

## regex/matched-value-override

Regex matched operator `re.group.N` value will be overriden.

These variables could use if(else) block statement when condition has regex operator like `~` or `!~`.
Note that group matched variable has potential of making bugs due to its spec:

1. re.group.N variable scope is subroutine-global, does not have block scope
2. matched value may override on second regex matching

For example:

```vcl
declare local var.S STRING;
set var.S = "foo bar baz";
if (req.http.Host) {
  if (var.S) {
    if (var.S !~ "(foo)\s(bar)\s(baz)") { // make matched values first (1)
      set req.http.First = "1";
    }
    set var.S = "hoge huga";
    if (var.S ~ "(hoge)\s(huga)") { // override matched values (2)
      set req.http.First = re.group.1;
    }
  }
  set req.http.Third = re.group.2; // difficult to know which (1) or (2) matched result is used
}

if (req.http.Host) {
  set req.http.Fourth = re.group.3; // difficult to know which (1) or (2) matched result is used or empty
}
```

## disallow-empty-return

A `return` statement in state-machine subroutine like `vcl_recv` must have the next state.

Problem:

```vcl
sub vcl_recv {
    ...
    return; // Must return with next state
}
```

Fix:

```vcl
sub vcl_recv {
    ...
    return (lookup);
}
```

Fastly document: https://developer.fastly.com/reference/vcl/subroutines#returning-a-state
