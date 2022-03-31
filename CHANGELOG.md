## v0.8.0

- Implement stats subcommand [#46](https://github.com/ysugimoto/falco/pull/46) (@ysugimoto)

## v0.7.3

- [bugfix] fix token point for missing semicolon [#44](https://github.com/ysugimoto/falco/pull/44) (@ysugimoto)

## v0.7.2

- [bugfix] Linting `client.geo.city.utf8` [#43](https://github.com/ysugimoto/falco/pull/43) (@davinci26)

## v0.7.1

- [bugfix] improve type comparison in set/add statement [#40](https://github.com/ysugimoto/falco/pull/40) (@ysugimoto)

## v0.7.0

- impl: Support access control list [#38](https://github.com/ysugimoto/falco/pull/38) (@ysugimoto)

## v0.6.1

- [bugfix] Fix builtin accessor and assign operator [#36](https://github.com/ysugimoto/falco/pull/36) (@ysugimoto)

## v0.6.0

- [bugfix] single argument should accept in randomstr function [#35](https://github.com/ysugimoto/falco/pull/35) (@ysugimoto)
- Implement unused definition/variable linting [#34](https://github.com/ysugimoto/falco/pull/34) (@ysugimoto)

## v0.5.0

- Rename main package to cmd/falco [#32](https://github.com/ysugimoto/falco/pull/32) (@xordspar0)

## v0.4.1

- Fix definition of TCP congestion parameters [#27](https://github.com/ysugimoto/falco/pull/27) (@bungoume)

## v0.4.0

- Implement regex validity linting [#26](https://github.com/ysugimoto/falco/pull/26) (@ysugimoto)
- Fix minor typo [#25](https://github.com/ysugimoto/falco/pull/25) (@shawnps)
- use context.Set() for set statement linter [#23](https://github.com/ysugimoto/falco/pull/23) (@smaeda-ks)

## v0.3.0

- fix: add statement linter [#22](https://github.com/ysugimoto/falco/pull/22) (@ysugimoto)
- impl: Support edge dictionary [#20](https://github.com/ysugimoto/falco/pull/20) (@ysugimoto)

## v0.2.3

- fix: prevent to die linter on return statement [#19](https://github.com/ysugimoto/falco/pull/19) (@ysugimoto)
- fix: nested block syntax could parse/lint [#18](https://github.com/ysugimoto/falco/pull/18) (@ysugimoto)

## v0.2.2

- Fix parsing infix block comments [#13](https://github.com/ysugimoto/falco/pull/13) (@dora1998)

## v0.2.1

- remove old file [#10](https://github.com/ysugimoto/falco/pull/10) (@ysugimoto)
- skip duplication check against Fastly's reserved subroutines [#9](https://github.com/ysugimoto/falco/pull/9) (@smaeda-ks)

## v0.2.0

- override severity via config [#7](https://github.com/ysugimoto/falco/pull/7) (@ysugimoto)
- boilerplate comment is not mandatory [#6](https://github.com/ysugimoto/falco/pull/6) (@smaeda-ks)
- fuzzy time type [#5](https://github.com/ysugimoto/falco/pull/5) (@ysugimoto)

## v0.1.0

First release
