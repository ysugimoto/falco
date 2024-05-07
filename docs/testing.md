# Unit Testing

You can run VCL unit test on our interpreter to make sure the subroutine works as you expected.

## Note

Some variables are limited because to interpreter runs locally, so the variables that are used in your production VCL may have unexpected values, and it may affect to testing. Please see [simulator documentation](https://github.com/ysugimoto/falco/blob/develop/docs/simulator.md) about limitations before.

## Usage

```
falco test -h
=========================================================
    ____        __
   / __/______ / /_____ ____
  / /_ / __  // //  __// __ \
 / __// /_/ // // /__ / /_/ /
/_/   \____//_/ \___/ \____/  Fastly VCL developer tool

=========================================================
Usage:
    falco test [flags]

Flags:
    -I, --include_path : Add include path
    -h, --help         : Show this help
    -r, --remote       : Connect with Fastly API
    -json              : Output results as JSON
    -request           : Override request config
    --max_backends     : Override max backends limitation
    --max_acls         : Override max acl limitation

Local testing example:
    falco test -I . -I ./tests /path/to/vcl/main.vcl
```

### Configuration

You can override default configurations via `.falco.yml` configuration file or cli arguments. See [configuration documentation](https://github.com/ysugimoto/falco/blob/develop/docs/configuration.md) in detail.


You can run testing as following:

```shell
falco test -I . /path/to/your/default.vcl
```

## How to write test VCL

When you run the testing command, falco finds test files that match the glob syntax of `*.test.vcl` in the `include_paths`, or you can override this by providing `-f,--filter` option to filter test target files you want.

Normally you can put the testing file in the same place as main VCL:

```shell
tree .

.
└── vcl
   ├── default.test.vcl  <= testing file
   └── default.vcl       <= main VCL

falco test ./vcl/default.vcl
```

Or, you may place testing files at a different directory, can place them and set more `include_paths` options on CLI:

```shell
tree .

.
├── vcl
│ └── default.vcl
└── vcl_tests
   └── default.test.vcl

falco test -I vcl_tests ./vcl/default.vcl
```

falco finds `default.test.vcl` as testing file for both case.

## Testing Subroutine

Unit testing file can be written as VCL subroutine, example is the following:

```vcl
// default.test.vcl

// @scope: recv
// @suite: Foo request header should contains "hoge"
sub test_vcl_recv {
  set req.http.Foo = "bar";
  testing.call_subroutine("vcl_recv");

  assert.equal(req.backend, httpbin_org);
  assert.contains(req.http.Foo, "hoge");
}

// @scope: deliver
// @suite: X-Custom-Header response header should contains "hoge"
sub test_vcl_deliver {
  set req.http.Foo = "bar";
  testing.call_subroutine("vcl_deliver");
  assert.contains(resp.http.X-Custom-Header, "hoge");
}
```

You can see many interesting syntaxes, The test case is controlled with annotation and assertion functions.

## Grouped Testing

falco supports special syntax of `describe`, `before_[scope]`, and `after_[scope]` - jest like syntax - only for the testing.
Here is the example of grouped testing:

```vcl
// Grouping test
describe grouped_tests {

    // run before recv scoped subroutine
    before_recv {
        // you can use variables that is enable to access in RECV scope
        set req.http.BeforeRecv = "1";
    }

    sub test_recv {
        // ensure http header which is injected via hook
        assert.equal(req.http.BeforeRecv, "1");
        // Do unit testing for RECV scope
    }

    ...
}
```

> [!NOTE]
> Testing subroutines are stateful through the grouped testing.
> A interpreter only be initialized for the group, the same interpreter will be used for each testing subroutine.
> It is useful for testing across scopes but this behavior may be different from the jest one.

### Scope Recognition

falco recognizes `@scope` annotation for execution scope.

`@scope: deliver` means the testing should run on `DELIVER` scope.
You can specify multiply by separating commas like `@scope: hit,pass`.

### Suite Name

You can specify the test suite name with `@suite` annotation value. Otherwise, the suite name will be set as the subroutine name.

### Testing preparation

When the test suite runs on a specific scope like `FETCH`, you need to set up a pre-condition to run target VCL.
It means you need to set up variables which is needed until the directive moves to `FETCH`, setting up before calling `testing.call_subroutine`.

This is because the test target subroutine (in this case, `vcl_fetch`) is called independently, so that the other lifecycle subroutines like `vcl_recv` and `vcl_pass` are not called.

For example:

```vcl
// @scope: fetch
// @suite: all needed variables are satisfied
sub pre_condition_test {

    // You need to set up some variables before calling "vcl_fetch".

    // Typically set query string might be set on vcl_recv.
    // But vcl_recv is not called in testing process, so you need to set in here.
    set req.url = quetystring.add(req.url, "foo", "bar")

    // Override backend response before calling "vcl_fetch" for test case of 500 status code.
    // It means there is a `hook` point before calling `vcl_fetch`.
    set beresp.status = 500;

    // call target subroutine
    testing.call_subroutine("vcl_fetch");

    // Some assertions below
    assert.equal(beresp.ttl, 1s) // TTL should be set 1s when status code is 500
}
```

### Testing Variables and Functions

On running tests, `falco` injects special runtime functions and variables to assert.

We describe them following table and examples:

| Name                         | Type       | Description                                                                                  |
|:-----------------------------|:----------:|:---------------------------------------------------------------------------------------------|
| testing.state                | STRING     | Return state which is called `return` statement in a subroutine                              |
| testing.call_subroutine      | FUNCTION   | Call subroutine which is defined in main VCL                                                 |
| testing.fixed_time           | FUNCTION   | Use fixed time whole the test suite                                                          |
| testing.override_host        | FUNCTION   | Override request host with provided argument in the test case                                |
| testing.inspect              | FUNCTION   | Inspect predefined variables for any scopes                                                  |
| testing.table_set            | FUNCTION   | Inject value for key to main VCL table                                                       |
| testing.table_merge          | FUNCTION   | Merge values from testing VCL table to main VCL table                                        |
| assert                       | FUNCTION   | Assert provided expression should be true                                                    |
| assert.true                  | FUNCTION   | Assert actual value should be true                                                           |
| assert.false                 | FUNCTION   | Assert actual value should be false                                                          |
| assert.is_notset             | FUNCTION   | Assert actual value should be NotSet                                                         |
| assert.equal                 | FUNCTION   | Assert actual value should be equal to expected value (alias of assert.strict_equal)         |
| assert.not_equal             | FUNCTION   | Assert actual value should not be equal to expected value (alias of assert.not_strict_equal) |
| assert.strict_equal          | FUNCTION   | Assert actual value should be equal to expected value strictly                               |
| assert.not_strict_equal      | FUNCTION   | Assert actual value should not be equal to expected value strictly                           |
| assert.equal_fold            | FUNCTION   | Assert actual value should be equal to with case insensitive                                 |
| assert.match                 | FUNCTION   | Assert actual string should be matched against expected regular expression                   |
| assert.not_match             | FUNCTION   | Assert actual string should not be matches against expected regular expression               |
| assert.contains              | FUNCTION   | Assert actual string should contain the expected string                                      |
| assert.not_contains          | FUNCTION   | Assert actual string should not contain the expected string                                  |
| assert.starts_with           | FUNCTION   | Assert actual string should start with expected string                                       |
| assert.ends_with             | FUNCTION   | Assert actual string should end with expected string                                         |
| assert.subroutine_called     | FUNCTION   | Assert subroutine has called in testing subroutine (with times)                              |
| assert.not_subroutine_called | FUNCTION   | Assert subroutine has not called in testing subroutine                                       |
| assert.restart               | FUNCTION   | Assert restart statement has called                                                          |
| assert.state                 | FUNCTION   | Assert after state is expected one                                                           |
| assert.error                 | FUNCTION   | Assert error status code (and response) if error statement has called                        |

----

### testing.call_subroutine(STRING subroutine)

Call subroutine that is defined at main VCL and included modules.
This function can also call Fastly reserved subroutine like `vcl_recv` for testing but ensure the call corresponds to the expected scope.

```vcl
// @scope: recv
sub test_vcl {
    // call vcl_recv Fastly reserved subroutine in RECV scope
    testing.call_subroutine("vcl_recv");
}
```

----

### testing.fixed_time(INTEGER|TIME|STRING time)

Use fixed time in the current test case.
After this function is called, `now` and `now.sec` always return the fixed time value. so it is useful for time-related tests, for example, checking session cookie is live or not.

The argument can accept some types:

- INTEGER: unix time seconds
- TIME: VCL time like std.integer2time() return value
- STRING: `YYYY-mm-dd HH:MM:SS` formatted string, human readable

```vcl
// @scope: recv
sub test_vcl {
    // Accepts INTEGER of unix time seconds
    testing.fixed_time(1694159940);

    // Accepts TIME that is made from VCL function
    testing.fixed_time(std.integer2time(1694159940));

    // Accepts STRING that has acceptable format
    testing.fixed_time("2023-09-08 16:59:00");

    // call vcl_recv Fastly reserved subroutine in RECV scope
    testing.call_subroutine("vcl_recv");

    // some time related assertions here
    assert.true(req.http.Is-Session-Expired)
}
```

----

### testing.override_host(STRING host)

Use fixed `Host` header in the current test case.
On the interpreter, the `Host` header value is always `localhost` and it inconvenient for the origin testing.
Then calling this function use a fixed `Host` header.

```vcl
// @scope: recv
sub test_vcl {
    // Use fixed host header
    testing.override_host("example.com");

    // call vcl_recv Fastly reserved subroutine in RECV scope
    testing.call_subroutine("vcl_recv");

    // some time related assertions here
    assert.true(resp.status == 200);
}
```

----

### testing.inspect(STRING var_name)

Inspect specific variable. This function has special permission that all variable value can inspect.

```vcl
// @scope: recv
sub test_vcl {
    // call vcl_recv Fastly reserved subroutine in RECV scope,
    // will call error statement in this subroutine.
    testing.call_subroutine("vcl_recv");

    // Typically obj.status could not access in recv scope,
    // but can inspect via this function.
    assert.equal(testing.inspect("obj.status"), 400);
}
```

----

### testing.table_set(ID table, STRING key, STRING value)

Inject value for key to main VCL table.

```vcl
// @scope: recv
sub test_vcl {
    // Inject table value
    testing.table_set(example_dict, "foo", "bar");

    // call vcl_recv Fastly reserved subroutine in RECV scope,
    // will call error statement in this subroutine.
    testing.call_subroutine("vcl_recv");

    // Assert injected value
    assert.equal(table.lookup(example_dict, "foo", ""), "bar");
}
```

----

### testing.table_merge(ID base, ID merge)

Merge values from testing VCL table to main VCL table.

```vcl

table merge_dict {
    "foo": "bar",
}

// @scope: recv
sub test_vcl {
    // Merge table value
    testing.table_merge(example_dict, merge_dict);

    // call vcl_recv Fastly reserved subroutine in RECV scope,
    // will call error statement in this subroutine.
    testing.call_subroutine("vcl_recv");

    // Assert injected value
    assert.equal(table.lookup(example_dict, "foo", ""), "bar");
}
```

----

### assert(ANY expr [, STRING message])

Assert provided expression should be truthy.
Note that the expression result must be `BOOL` or `STRING` type to evaluate value is truthy.
Otherwise, the assertion failed with `TypeMismatch`.

```vcl
sub test_vcl {
    declare local var.testing STRING;

    set var.Testing = "foo";
    set req.http Foo = "foo";

    // Pass because expression to be true
    assert(req.http.Foo == var.testing);

    // Pass because expression is thuthy
    assert(req.http.Foo);

    // Fail because expression to be false
    assert(req.http.Foo == "bar");
}
```

----

### assert.true(ANY actual [, STRING message])

Assert actualvalue should be `true`.

```vcl
sub test_vcl {
    declare local var.testing BOOL;

    set var.testing = true;

    // Pass because value is true
    assert.true(var.testing);

    // Pass because expression value is  true
    assert.true(var.testing == true);

    // Fail because experssion value is not BOOL true
    assert.true(req.http.Foo);
}
```

----

### assert.false(ANY actual [, STRING message])

Assert actualvalue should be `false`.

```vcl
sub test_vcl {
    declare local var.testing BOOL;

    // Pass because value is false
    assert.false(var.testing);

    // Pass because expression value is  false
    assert.false(var.testing != true);

    // Fail because experssion value is not BOOL false
    assert.false(req.http.Foo);
}
```

----

### assert.is_notset(ANY actual [, STRING message])

Assert actualvalue should be [NotSet](https://developer.fastly.com/reference/vcl/types/#not-set).

```vcl
sub test_vcl {
    declare local var.testing STRING;

    // Pass because value is NotSet
    assert.is_notset(var.testing);

    set var.testing = "";

    // Fail because value is empty, not NotSet
    assert.is_notset(var.testing);

    // Pass because value is NotSet
    assert.is_notset(req.http.Foo);
}
```

----

### assert.strict_equal(ANY actual, ANY expect [, STRING message])

Assert actual value should be equal to the expected value.
Note that falco asserts strict type equality so both value types must be equal too.

```vcl
sub test_vcl {
    declare local var.testing STRING;
    declare local var.testing2 INTEGER;

    set var.testing = "foo";
    set var.testing2 = 10;

    // Pass because value is equal
    assert.strict_equal(var.testing, "foo");

    // Fail because value is not equal
    assert.strict_equal(var.testing, "bar");

    // Fail because value type is not equal
    assert.strict_equal(var.testing, var.testing2);
}
```

----

### assert.not_strict_equal(ANY actual, ANY expect [, STRING message])

Assert actual value should NOT be equal to the expected value.

```vcl
sub test_vcl {
    declare local var.testing STRING;
    declare local var.testing2 INTEGER;

    set var.testing = "foo";
    set var.testing2 = 10;

    // Fail because value is equal
    assert.not_strict_equal(var.testing, "foo");

    // Pass because value is not equal
    assert.not_strict_equal(var.testing, "bar");

    // Fail because value type is not equal
    assert.not_strict_equal(var.testing, var.testing2);
}
```

----

### assert.equal_fold(STRING actual, STRING expect [, STRING message])

Assert actual value should be equal to the expected value as case insensitive.

```vcl
sub test_vcl {
    declare local var.testing STRING;
    declare local var.testing2 INTEGER;

    set var.testing = "foo";

    // Pass because value is equal with case insensitive
    assert.strict_equal(var.testing, "Foo");
}
```

----

### assert.equal(ANY actual, ANY expect [, STRING message])

Alias of `assert.strict_equal`.

----

### assert.not_equal(ANY actual, ANY expect [, STRING message])

Alias of `assert.not_strict_equal`.

----

### assert.match(STRING actual, STRING expect [, STRING message])

Assert actual string should be matched against expected regular expression.

```vcl
sub test_vcl {
    declare local var.testing STRING;

    set var.testing = "foobarbaz";

    // Pass because value matches regular expression
    assert.match(var.testing, ".+bar.+");

    // Fail because value does not match regular expression
    assert.match(var.testing, "bar");

    // Fail because value type is not a string
    assert.match(client.ip, "10");
}
```

----

### assert.not_match(STRING actual, STRING expect [, STRING message])

Assert actual string should NOT be matched against expected regular expression.

```vcl
sub test_vcl {
    declare local var.testing STRING;

    set var.testing = "foobarbaz";

    // Pass because value does not matche regular expression
    assert.not_match(var.testing, ".+other.+");

    // Fail because value matches regular expression
    assert.not_match(var.testing, "^foo");
}
```

----

### assert.contains(STRING actual, STRING expect [, STRING message])

Assert actual string should be contained in expected string.

```vcl
sub test_vcl {
    declare local var.testing STRING;

    set var.testing = "foobarbaz";

    // Pass because value contains "baz"
    assert.contains(var.testing, "baz");

    // Fail because value does not contain "other"
    assert.contains(var.testing, "other");
}
```

----

### assert.not_contains(STRING actual, STRING expect [, STRING message])

Assert actual string should NOT be contained in expected string.

```vcl
sub test_vcl {
    declare local var.testing STRING;

    set var.testing = "foobarbaz";

    // Pass because value does not contain "other"
    assert.not_contains(var.testing, "other");

    // Fail because value contains "baz"
    assert.not_contains(var.testing, "baz");
}
```

----

### assert.starts_with(STRING actual, STRING expect [, STRING message])

Assert the actual string should start with the expected string.

```vcl
sub test_vcl {
    declare local var.testing STRING;

    set var.testing = "foobarbaz";

    // Pass because value starts with "foo"
    assert.starts_with(var.testing, "foo");

    // Fail because value does not start with "bar"
    assert.starts_with(var.testing, "bar");
}
```

----

### assert.ends_with(STRING actual, STRING expect [, STRING message])

Assert actual string should end with the expected string.

```vcl
sub test_vcl {
    declare local var.testing STRING;

    set var.testing = "foobarbaz";

    // Pass because value ends with "baz"
    assert.ends_with(var.testing, "baz");

    // Fail because value does not end with "bar"
    assert.ends_with(var.testing, "bar");
}
```

----

### assert.subroutine_called(STRING name [, INTEGER times, STRING message])

Assert subroutine has called in testing subroutine (with times).

```vcl
sub test_vcl {
    // Like "auth_recv" subroutine will be called in vcl_recv
    testing.call_subroutine("vcl_recv");

    // Assert "auth_recv" subroutine has called in processing vcl_recv
    assert.subroutine_called("auth_recv");

    // Additionally, "auth_recv" called only once
    assert.subroutine_called("auth_recv", 1);
}
```

----

### assert.not_subroutine_called(STRING name [, STRING message])

Assert subroutine has not called in testing subroutine (with times).

```vcl
sub test_vcl {
    // Like "auth_recv" subroutine will be called in vcl_recv
    testing.call_subroutine("vcl_recv");

    // Assert "flag_recv" subroutine has not called in processing vcl_recv
    assert.not_subroutine_called("flag_recv");
}
```

----

### assert.restart([, STRING message])

Assert restart statement has called.

```vcl
sub test_vcl {
    // restart statement will be called on some request condition
    testing.call_subroutine("vcl_recv");

    // Assert restart statement has called
    assert.restart();
}
```

----

### assert.state(ID state [, STRING message])

Assert current state is expected.

```vcl
sub test_vcl {
    // vcl_recv will move state to lookup to lookup cache
    testing.call_subroutine("vcl_recv");

    // Assert state moves to lookup
    assert.state(lookup);
}
```

----

### assert.error(INTEGER status [, STRING response, STRING message])

Assert error status code (and response) if error statement has called.

```vcl
sub test_vcl {
    // vcl_recv will call error statement with status code and response
    testing.call_subroutine("vcl_recv");

    // Assert error statement has called with expected status
    assert.error(900);

    // Assert error statement has called with expected status and response text
    assert.error(900, "Fastly Internal");
}
```

