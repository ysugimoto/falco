# Unit Testing

You can run VCL unit test on our interpreter to make sure the subroutine works as expected.

Note that the test runner runs on our VCL interpreter, so please see [simulator documentation](https://github.com/ysugimoto/falco/blob/develop/docs/simulator.md) and its limitations before.

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

When you run testing command, falco finds test files which have `.test.vcl` suffix in the `include_paths`.
Normally you can put testing file at the same place of main VCL:

```shell
tree .

.
└── vcl
   ├── default.test.vcl  <= testing file
   └── default.vcl       <= main VCL

falco test ./vcl/default.vcl
```

Or, you may place testing files at the different directory, you can place them and set more `include_paths` option on CLI:

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

Unit testing file can be written as VCL subroutine, example is following:

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

You can see many interesting syntax, The test case is controlled with annotation and assertion functions.

### Scope Recognition

falco recognize `@scope` annotation for execution scope.

`@scope: deliver` means the testing should run on `DELIVER` scope.
You can specify multiply by separating comma like `@scope: hit,pass`.

### Suite Name

You can specify test suite name with `@suite` annotation value. Otherwise, the suite name will set as subroutine name.

### Testing preparetion

When test suite runs on the specific scope like `FETCH`, you need to set up pre-condition to run target VCL.
It means you need to set up variables which is needed until directive moves to `FETCH`, setting up before calling `testing.call_subroutine`.

This is because test target subroutine (in this case, `vcl_fetch`) is called independently, so thet the other lifecycle subroutines like `vcl_recv` and `vcl_pass` are not called.

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
    // It means here is a `hook` point before calling `vcl_fetch`.
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

| Name                    | Type       | Description                                                                                  |
|:------------------------|:----------:|:---------------------------------------------------------------------------------------------|
| testing.state           | STRING     | Return state which is called `return` statement in a subroutine                              |
| testing.call_subroutine | FUNCTION   | Call subroutine which is defined in main VCL                                                 |
| assert                  | FUNCTION   | Assert provided expression should be true                                                    |
| assert.true             | FUNCTION   | Assert actual value should be true                                                           |
| assert.false            | FUNCTION   | Assert actual value should be false                                                          |
| assert.equal            | FUNCTION   | Assert actual value should be equal to expected value (alias of assert.strict_equal)         |
| assert.not_equal        | FUNCTION   | Assert actual value should not be equal to expected value (alias of assert.not_strict_equal) |
| assert.strict_equal     | FUNCTION   | Assert actual value should be equal to expected value strictly                               |
| assert.not_strict_equal | FUNCTION   | Assert actual value should not be equal to expected value strictly                           |
| assert.match            | FUNCTION   | Assert actual string should be matched against expected regular expression                   |
| assert.not_match        | FUNCTION   | Assert actual string should not be matches against expected regular expression               |
| assert.contains         | FUNCTION   | Assert actual string should contain the expected string                                      |
| assert.not_contains     | FUNCTION   | Assert actual string should not contain the expected string                                  |
| assert.starts_with      | FUNCTION   | Assert actual string should start with expected string                                       |
| assert.ends_with        | FUNCTION   | Assert actual string should end with expected string                                         |

----

### testing.call_subroutine(STRING subroutine)

Call subroutine that is defined at main VCL and included modules.
This function can also call Fastly reserved subroutine like `vcl_recv` for testing but ensure call with corresponds to expected scope.

```vcl
// @scope: recv
sub test_vcl {
    // call vcl_recv Fastly reserved subroutine in RECV scope
    testing.call_subroutine("vcl_recv");
}
```

----

### assert(ANY expr [, STRING message])

Assert provided expression should be truthy.
Note that expression result must be `BOOL` or `STRING` type to evaluate value is truthy.
Otherwise, assertion failed with `TypeMismatch`.

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

### assert.strict_equal(ANY actual, ANY expect [, STRING message])

Assert actual value should be equal to expected value.
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

Assert actual value should NOT be equal to expected value.

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

Assert actual string should NOT be matches against expected regular expression.

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

Assert actual string should start with expected string.

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

Assert actual string should end with expected string.

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
