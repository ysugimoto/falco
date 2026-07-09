# Parser spec

`falco` parses based on the following language spec of VCL.
Especially about comment, you can write comments on the `<comment>` placeholder.

If you write an VCL without following spec, parser may raise an error or lack comments so you might need to move or delete them.

## ACL Declaration

```
acl <comment> <acl_name> <comment> {
    <comment>
    <!> <comment> "<ip_address>"</><mask> <comment>; <comment>
    ...
} <comment>
```

## Backend Declaration

```
backend <comment> <backend_name> <comment> {
    <comment>
    .<property_name> <comment> = <comment> <property_value> <comment>; <comment>
    ...

    .probe <comment> = <comment> {
      <comment>
      .<property_name> <comment> = <comment> <property_value> <comment>; <comment>
      ...
    } <comment>
} <comment>
```

## Director Declaration

```
director <comment> <director_name> <comment> <director_type> <comment> {
    <comment>
    .<property_name> <comment> = <comment> <property_value> <comment>; <comment>
    ...

    {<comment> .<property_name> <comment> = <comment> <property_value> <comment>; <comment>} <comment>
    ...
} <comment>
```

## Table Declaration

```
table <comment> <table_name> <comment> <value_type> <comment> {
    <comment>
    "<property_name>" <comment>: <comment> <property_value> <comment>, <comment>
    ...
}
```

## Subroutine Declaration

```
sub <comment> <subroutine_name> <comment> {
    <statement>...
    <comment>
} <comment>
```

## Penaltybox Declaration

```
penaltybox <comment> <penaltybox_name> <comment> {
    <comment>
} <comment>
```

## Ratecounter Declaration

```
ratecounter <comment> <ratecounter_name> <comment> {
    <comment>
} <comment>
```

## Add Statement

```
<comment>
add <comment> <identifier> <comment> = <comment> <value> <comment>; <comment>
```

## Block Statement

```
<comment>
{
    <statement>...
    <comment>
} <comment>
```

## Call Statement

```
<comment>
call <comment> <subroutine_name> <comment>; <comment>
```

## Declare Statement

```
<comment>
declare <comment> local <comment> <variable_name> <comment> <variable_type> <comment>; <comment>
```

## Error Statement

```
<comment>
error <comment> <status_code> <comment> <arguments>... <comment>; <comment>
```

## Esi Statement

```
<comment>
esi <comment>; <comment>
```

## Function Call Statement

```
<comment>
<function_name>(<comment> <argument> <comment>, ...) <comment>; <comment>
```

## Goto Statement

```
<comment>
goto <comment> <goto_target> <comment>; <comment>
```

## Goto Target Statement

```
<comment>
<goto_target>: <comment>
```

## If Statement

```
<comment>
if <comment> (<comment> <expression> <comment>) <comment> {
    <statement>...
}
<comment>
else if <comment> (<comment> <expression> <comment>) <comment> {
    <statement>...
}
<comment>
else <comment> {
    <statement>...
}
```

## Import Statement

```
<comment>
import <comment> <module_name> <comment>; <comment>
```

## Include Statement

```
<comment>
include <comment> <module_name> <comment>; <comment>
```

## Log Statement

```
<comment>
log <comment> <expression> <comment>...; <comment>
```

## Remove Statement

```
<comment>
remove <comment> <identifier> <comment>; <comment>
```

## Restart Statement

```
<comment>
restart <comment>; <comment>
```

## Return Statement

```
<comment>
return <comment> (<comment> <state> <comment>) <comment>; <comment>
```

Parenthesis is arbitrary.

## Set Statement

```
<comment>
set <comment> <identifier> <comment> = <comment> <value> <comment>; <comment>
```

## Switch Statement

```
<comment>
switch <comment> (<comment> <expression> <comment>) <comment> {
    <comment>
    case <comment> <expression> <comment>: <comment>
        <statement>...
        <comment>
        fallthrough <comment>; <comment>
        <comment>
        break <comment>; <comment>
    default <comment>: <comment>
        <statement>...
}
```

## Synthetic Statement

```
<comment>
synthetic <comment> <expression> <comment>...; <comment>
```

## Synthetic Base64 Statement

```
<comment>
synthetic.base64 <comment> <expression> <comment>...; <comment>
```

## Unset Statement

```
<comment>
unset <comment> <identifier> <comment>; <comment>
```

About BNF of VCL, see https://gist.github.com/benediktkr/52d33ca982e29916a8aa

## Numeric Literals

`falco` recognizes the following numeric literal forms.

### Integers

- Decimal: `100`, `0` and a leading zero is decimal, not octal (e.g. `0755` == 755).
- Hexadecimal: a `0x`/`0X` prefix followed by hex digits (`0x5a5a`, `0Xff`, `0x7FFFFFFFFFFFFFFF`).

An integer literal's magnitude must fit a signed 64-bit value (`INT_MAX` ==
`0x7FFFFFFFFFFFFFFF`). The single exception is `2^63` (`0x8000000000000000` /
`9223372036854775808`), which is accepted only as the operand of a unary minus
to express `INT_MIN` (`-0x8000000000000000`). A bare positive `2^63`, a uint64
"mask" such as `0xFFFFFFFFFFFFFFFF`, and any larger magnitude are rejected as a
signed integer overflow, matching Fastly.

### Floats

- Decimal with a fractional part: `10.0`, `1.5`.
- Decimal with a lowercase `e` exponent: `1e3`, `1.5e3`, `1e-3`, `1e+3`.
- Hexadecimal floats with a lowercase `p` binary exponent: `0x1.8p3`, `0xA.Bp3`.
  The `p` exponent may be omitted (`0x1.8`), in which case it defaults to `p0`.

Exponent markers are lowercase only (`1E3` and `0x1.8P3` are rejected by Fastly,
so `falco` rejects them too). The source representation of a literal is preserved
through linting, formatting and serialization (e.g. `0x5a5a` is emitted as
`0x5a5a`, not `23130`).

Numeric literals that carry a hexadecimal prefix or an exponent cannot be
combined with an [RTIME](https://developer.fastly.com/reference/vcl/types/rtime/)
unit suffix; only plain decimal literals form an RTIME (e.g. `100ms`, `1.5s`).
