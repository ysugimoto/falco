# Linter rules

This file describes `falco` linter rules and how to fix it.

### acl/syntax

Syntax error on ACL definition.

Acl syntax is:

```vcl
acl (?<acl_name>[a-zA-Z0-9_]+) {
  (?<inverse>!?)(?<ip_address>"[0-9\.]+")(/?)(?<cidr_mask>[0-9]+);
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

Fastly Document : https://developer.fastly.com/reference/vcl/declarations/acl/


### acl/duplicated

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

### backend/syntax

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

### backend/duplicated

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

### backend/notfound

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

### director/syntax

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

### director/duplicated

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

### director/props-random

Required property is not declared on `random` director.

Fastly document: https://developer.fastly.com/reference/vcl/declarations/director/#random

### director/props-fallback

Required property is not declared on `fallback` director.

Fastly document: https://developer.fastly.com/reference/vcl/declarations/director/#fallback

### director/props-hash

Required property is not declared on `hash` director.

Fastly document: https://developer.fastly.com/reference/vcl/declarations/director/#content

### director/props-client

Required property is not declared on `client` director.

Fastly document: https://developer.fastly.com/reference/vcl/declarations/director/#client

### director/props-chash

Required property is not declared on `chash` director.

Fastly document: https://developer.fastly.com/reference/vcl/declarations/director/#consistent-hashing

### director/backend-required

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

### table/syntax
	TABLE_SYNTAX:                     "https://developer.fastly.com/reference/vcl/declarations/table/",
### table/type-variation
	TABLE_TYPE_VARIATION:             "https://developer.fastly.com/reference/vcl/declarations/table/#type-variations",
### table/item-limitation
	TABLE_ITEM_LIMITATION:            "https://developer.fastly.com/reference/vcl/declarations/table/#limitations",
### table/duplicated
### subroutine/syntax
	SUBROUTINE_SYNTAX:                "https://developer.fastly.com/reference/vcl/subroutines/",
### subroutine/boilerplate-macro
	SUBROUTINE_BOILERPLATE_MACRO:     "https://developer.fastly.com/learning/vcl/using/#adding-vcl-to-your-service-configuration",
### subroutine/duplicated
### declare-statement/syntax
	DECLARE_STATEMENT_SYNTAX:         "https://developer.fastly.com/reference/vcl/variables/#user-defined-variables",
### declare-statement/invalid-type
	DECLARE_STATEMENT_INVALID_TYPE:   "https://developer.fastly.com/reference/vcl/variables/#user-defined-variables",
### declare-statement/duplicated
### set-statement/syntax
	SET_STATEMENT_SYNTAX:             "https://developer.fastly.com/reference/vcl/statements/set/",
### operator/assignment
	OPERATOR_ASSIGNMENT:              "https://developer.fastly.com/reference/vcl/operators/#assignment-operators",
### unset-statement/syntax
	UNSET_STATEMENT_SYNTAX:           "https://developer.fastly.com/reference/vcl/statements/unset/",
### remove-statement/syntax
	REMOVE_STATEMENT_SYNTAX:          "https://developer.fastly.com/reference/vcl/statements/remove/",
### operator/conditional
	OPERATOR_CONDITIONAL:             "https://developer.fastly.com/reference/vcl/operators/#conditional-operators",
### restart-statement/scope
	RESTART_STATEMENT_SCOPE:          "https://developer.fastly.com/reference/vcl/statements/restart/",
### add-statement/syntax
	ADD_STATEMENT_SYNTAX:             "https://developer.fastly.com/reference/vcl/statements/add/",
### call-statement/syntax
	CALL_STATEMENT_SYNTAX:            "https://developer.fastly.com/reference/vcl/statements/call/",
### call-statement/subroutine-notfound
### error-statement/scope
	ERROR_STATEMENT_SCOPE:            "https://developer.fastly.com/reference/vcl/statements/error/",
### error-statement/code
	ERROR_STATEMENT_CODE:             "https://developer.fastly.com/reference/vcl/statements/error/#best-practices-for-using-status-codes-for-errors",
### synthetic-statement/scope
	SYNTHETIC_STATEMENT_SCOPE:        "https://developer.fastly.com/reference/vcl/statements/synthetic/",
### synthetic-base64-statement/scope
	SYNTHETIC_BASE64_STATEMENT_SCOPE: "https://developer.fastly.com/reference/vcl/statements/synthetic-base64/",
### condition/literal
### valid-ip
### function/arguments
### function/argument-type
### include/module-not-found
### include/module-load-failed
### regex/matched-value-override
