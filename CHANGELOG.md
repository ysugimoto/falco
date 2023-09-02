## v0.24.0

- add new predefined/builtins, implement checker [#171](https://github.com/ysugimoto/falco/pull/171) (@ysugimoto)

## v0.23.2

- fix up output methods on runne [#161](https://github.com/ysugimoto/falco/pull/161) (@ysugimoto)

## v0.23.1

- Adds copy-edits for output [#158](https://github.com/ysugimoto/falco/pull/158) (@doramatadora)

## v0.23.0

- Adds JSON support for generic, terraform and lint usage [#157](https://github.com/ysugimoto/falco/pull/157) (@doramatadora)

## v0.22.0

- Add fastly_info.host_header [#155](https://github.com/ysugimoto/falco/pull/155) (@bungoume)

## v0.21.0

- Integrate configuration to config package [#151](https://github.com/ysugimoto/falco/pull/151) (@ysugimoto)

## v0.20.3

- Accept `.backend` in chash director [#149](https://github.com/ysugimoto/falco/pull/149) (@davinci26)
- Fix resolving Terraform Modules [#148](https://github.com/ysugimoto/falco/pull/148) (@shadialtarsha)

## v0.20.1

- support private edge dictionary [#144](https://github.com/ysugimoto/falco/pull/144) (@ysugimoto)

## v0.20.0

- implement ignoring feature [#124](https://github.com/ysugimoto/falco/pull/124) (@ysugimoto)

## v0.19.1

- supress output [#123](https://github.com/ysugimoto/falco/pull/123) (@ysugimoto)

## v0.19.0

- Lint include statement on its place [#119](https://github.com/ysugimoto/falco/pull/119) (@ysugimoto)
- Implement fastly managed snippets linting [#120](https://github.com/ysugimoto/falco/pull/120) (@ysugimoto)
- fix fourth argument type of accept.language_filter_basic [#121](https://github.com/ysugimoto/falco/pull/121) (@ysugimoto)

## v0.18.0

- Add support for PCRE [#90](https://github.com/ysugimoto/falco/pull/90) (@shadialtarsha)

## v0.17.0

- Sanitize invalid chars in backend name before adding them as snippets [#106](https://github.com/ysugimoto/falco/pull/106) (@davinci26)
- Add more implicit conversion fuzy types [#107](https://github.com/ysugimoto/falco/pull/107) (@davinci26)
- lint protected HTTP headers [#108](https://github.com/ysugimoto/falco/pull/108) (@ysugimoto)
- Fix error with ast.GOTO and Encoder [#109](https://github.com/ysugimoto/falco/pull/109) (@davinci26)
- display actual line and position even identity is not found in context [#112](https://github.com/ysugimoto/falco/pull/112) (@ysugimoto)
- treat obective access in req.http contains semicolon character [#113](https://github.com/ysugimoto/falco/pull/113) (@ysugimoto)
- fix panic error for getting remote snippet [#115](https://github.com/ysugimoto/falco/pull/115) (@ysugimoto)
- correct parser for reserved word [#117](https://github.com/ysugimoto/falco/pull/117) (@ysugimoto)

## v0.16.0

- Allow req.backend to be read as a string [#96](https://github.com/ysugimoto/falco/pull/96) (@ivomurrell)
- Combine included VCL modules into main and parse once [#93](https://github.com/ysugimoto/falco/pull/93) (@ysugimoto)
- Add missing backend property [#100](https://github.com/ysugimoto/falco/pull/100) (@davinci26)
- Adds Tests for examples [#101](https://github.com/ysugimoto/falco/pull/101) (@davinci26)

## v0.15.0

- Allow function expressions in error statements [#94](https://github.com/ysugimoto/falco/pull/94) (@ivomurrell)
- Fetch backend snippets from Fastly API [#95](https://github.com/ysugimoto/falco/pull/95) (@ivomurrell)


## v0.14.0

- Allow calling functions with parentheses [#92](https://github.com/ysugimoto/falco/pull/92) (@shadialtarsha)
- Fix lint of log statement [#91](https://github.com/ysugimoto/falco/pull/91) (@davinci26)
- Add new VCL predefined variables [#89](https://github.com/ysugimoto/falco/pull/89) (@bungoume)
- String list arguments [#82](https://github.com/ysugimoto/falco/pull/82) (@ysugimoto)

## v0.13.0

- Add support for function calls as statements [#73](https://github.com/ysugimoto/falco/pull/73) (@shadialtarsha)

## v0.12.0

- Add support for Goto declaration [#72](https://github.com/ysugimoto/falco/pull/72) (@shadialtarsha)
- Updates types for resp.tarpit [#74](https://github.com/ysugimoto/falco/pull/74) (@davinci26)
- Adds support for h3.alt_svc function [#75](https://github.com/ysugimoto/falco/pull/75) (@davinci26)
- Improve include statement parsing [#77](https://github.com/ysugimoto/falco/pull/77) (@davinci26)

## v0.11.0

- Respect Ratelimit variables in context [#67](https://github.com/ysugimoto/falco/pull/67) (@shadialtarsha)
- Add warning for backend health check prober [#64](https://github.com/ysugimoto/falco/pull/64) (@davinci26)
- Adds support for subs with return type [#57](https://github.com/ysugimoto/falco/pull/57) (@davinci26)

## v0.10.0

- Add support for Fastly Rate Limiting [#60](https://github.com/ysugimoto/falco/pull/60) (@shadialtarsha)
- fix ci linting [#61](https://github.com/ysugimoto/falco/pull/61) (@ysugimoto)

## v0.9.2

- Support platform of `alipne`, `darwin-arm64` [#55](https://github.com/ysugimoto/falco/pull/55) (@ysugimoto)

## v0.9.1

- Tweak multiple service linting for terraform [#54](https://github.com/ysugimoto/falco/pull/54) (@ysugimoto)
  - extend stdin timeout, `terraform show -json` command might be a few seconds to output them
- Support legacy Fastly Provider service definition of `fastly_service_v1`
- Fix ident parse for table property value
  - If some declaration access in table property, it should be marked as used

## v0.9.0

- Improve waf related variables [#49](https://github.com/ysugimoto/falco/pull/49) (@ysugimoto)
- Allow subroutine hoisting [#52](https://github.com/ysugimoto/falco/pull/52) (@ysugimoto)
- Support linting multiple services [#53](https://github.com/ysugimoto/falco/pull/53) (@ysugimoto)

## v0.8.0

- Support terraform [#48](https://github.com/ysugimoto/falco/pull/48) (@ysugimoto)

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
