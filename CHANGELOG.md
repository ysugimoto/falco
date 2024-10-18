## v1.11.0

- add dap subcommand and support basic DAP features [#349](https://github.com/ysugimoto/falco/349) (@rinx)
- Fix tiny bug of base64 decode functions [#351](https://github.com/ysugimoto/falco/351) (@ysugimoto)
- implement `assert.not_error` assertion method [#352](https://github.com/ysugimoto/falco/352) (@ysugimoto)
- fix header existence logic, exactly treat as null or empty string [#353](https://github.com/ysugimoto/falco/353) (@ysugimoto)
- improve url encode and decode built-in functions [#354](https://github.com/ysugimoto/falco/354) (@ysugimoto)
- move base64 related logic to shared codec [#355](https://github.com/ysugimoto/falco/355) (@ysugimoto)
- Fix hex display: pad 01-0F values to two digits [#356](https://github.com/ysugimoto/falco/356) (@bungoume)
- fix literal comparing issue for injected variables [#357](https://github.com/ysugimoto/falco/357) (@ysugimoto)
- add `bereq.max_reuse_idle_time` variable support [#362](https://github.com/ysugimoto/falco/362) (@ysugimoto)
- add remote director resource to lint [#363](https://github.com/ysugimoto/falco/363) (@ysugimoto)
- Improve string concatenation logic [#364](https://github.com/ysugimoto/falco/364) (@ysugimoto)
- implement raising deprecated error [#366](https://github.com/ysugimoto/falco/366) (@ysugimoto)
- docs(dap): add a brief documentation about dap subcommand [#367](https://github.com/ysugimoto/falco/367) (@rinx)

## v1.10.0

- add watch option for incremental testing [#347](https://github.com/ysugimoto/falco/347) (@ysugimoto)
- exact custom token [#346](https://github.com/ysugimoto/falco/346) (@ysugimoto)
- implement uuid version7 related new functions [#345](https://github.com/ysugimoto/falco/345) (@ysugimoto)
- inject value for tentative in simulator [#344](https://github.com/ysugimoto/falco/344) (@ysugimoto)
- correct typo in SortDeclaration default tag [#342](https://github.com/ysugimoto/falco/342) (@acme)
- adjust default TrailingCommentWidth to 1 [#341](https://github.com/ysugimoto/falco/341) (@acme)
- update timezone in test [#340](https://github.com/ysugimoto/falco/340) (@acme)
- add `--genearted` option and add vcl_pipe related linter rule [#339](https://github.com/ysugimoto/falco/339) (@ysugimoto)
- support Fastly generated specific syntaxes [#338](https://github.com/ysugimoto/falco/338) (@ysugimoto)

## v1.9.1

- strict macro linting [#336](https://github.com/ysugimoto/falco/336) (@ysugimoto)
- feat(formatter): prevent indentation of #FASTLY macros [#335](https://github.com/ysugimoto/falco/335) (@acme)
- fix(formatter): remove space between return and parenthesis [#334](https://github.com/ysugimoto/falco/334) (@acme)
- Add feature to disable only specific lint rules with ignore comment [#333](https://github.com/ysugimoto/falco/333) (@nodaguti)
- Set exit code to 1 when there are one or more lint errors [#332](https://github.com/ysugimoto/falco/332) (@nodaguti)
- Add extra format check for backend.share_key [#331](https://github.com/ysugimoto/falco/331) (@nodaguti)
- Fix broken result message of tester and use exactly the same format for both passed and failed tests [#330](https://github.com/ysugimoto/falco/330) (@nodaguti)

## v1.9.0

- Arbitrary process flow marking [#327](https://github.com/ysugimoto/falco/pull/327) (@ysugimoto)
- Actual proxy behavior in simulator [#328](https://github.com/ysugimoto/falco/pull/328) (@ysugimoto)
- Reduce memory allocation using pool [#329](https://github.com/ysugimoto/falco/pull/329) (@ysugimoto)

## v1.8.0

- HTTPS server Support [#319](https://github.com/ysugimoto/falco/pull/319) (@ysugimoto)
- Support fastly.try_select_shield new function [#320](https://github.com/ysugimoto/falco/pull/320) (@ysugimoto)
- Injectable Edge Dictionary on Simulator [#321](https://github.com/ysugimoto/falco/pull/321) (@ysugimoto)
- Subroutine mocking feature [#322](https://github.com/ysugimoto/falco/pull/322) (@ysugimoto)
- Bump versions on CI [#323](https://github.com/ysugimoto/falco/pull/323) (@ysugimoto)
- Implement plugin system [#324](https://github.com/ysugimoto/falco/pull/324) (@ysugimoto)

## v1.7.0

- Feature/testing syntax [#312](https://github.com/ysugimoto/falco/pull/312) (@ysugimoto)
- Add linter rule of goto [#311](https://github.com/ysugimoto/falco/pull/311) (@ysugimoto)

## v1.6.0

- Errors with concurrent simulator requests due to global interpreter state [#282](https://github.com/ysugimoto/falco/pull/282) (@richardmarshall)
- Fix offset/length handling in substr & utf8.substr [#283](https://github.com/ysugimoto/falco/pull/283) (@richardmarshall)
- Regex patterns must be literals [#284](https://github.com/ysugimoto/falco/pull/284) (@richardmarshall)
- Add missing backend.{name}.* variables [#285](https://github.com/ysugimoto/falco/pull/285) (@richardmarshall)
- Feature/implement formatter [#291](https://github.com/ysugimoto/falco/pull/291) (@ysugimoto)
- Add enforcing and ignoring subroutine scope in linter config [#296](https://github.com/ysugimoto/falco/pull/296) (@ysugimoto)
- Improve parser/ast for complex comments [#302](https://github.com/ysugimoto/falco/pull/302) (@ysugimoto)
- Feature/console subcommand [#303](https://github.com/ysugimoto/falco/pull/303) (@ysugimoto)


## v1.5.0

- Add assert.not_subroutine_called [#247](https://github.com/ysugimoto/falco/pull/247) (@bungoume)
- Save/restore current subroutine locals when processing call statement [#254](https://github.com/ysugimoto/falco/pull/254) (@richardmarshall)
- Handle % string escapes [#256](https://github.com/ysugimoto/falco/pull/256) (@richardmarshall)
- testing.call_subroutine ignores invalid subroutine name [#259](https://github.com/ysugimoto/falco/pull/259) (@akrainiouk)
- fixed double decoding in urldecod [#261](https://github.com/ysugimoto/falco/pull/261) (@akrainiouk)
- req.url: fixed consistency with Fastly implementation [#262](https://github.com/ysugimoto/falco/pull/262) (@akrainiouk)
- fix base64 decode related builtin function [#263](https://github.com/ysugimoto/falco/pull/263) (@ysugimoto)
- Fixed parsing of += operator [#266](https://github.com/ysugimoto/falco/pull/266) (@akrainiouk)
- keepalive_time added to supported backend properties [#269](https://github.com/ysugimoto/falco/pull/269) (@akrainiouk)
- improve trailing/infix comment parsing [#270](https://github.com/ysugimoto/falco/pull/270) (@ysugimoto)
- follow new fastly documentation [#271](https://github.com/ysugimoto/falco/pull/271) (@ysugimoto)
- special dealing for req.hash addition assignment [#275](https://github.com/ysugimoto/falco/pull/275) (@ysugimoto)
- Prioritize cache object [#277](https://github.com/ysugimoto/falco/pull/277) (@richardmarshall)
- fix exprression comment parsing [#278](https://github.com/ysugimoto/falco/pull/278) (@ysugimoto)
- Setup req.http.host in ProcessInit [#279](https://github.com/ysugimoto/falco/pull/279) (@richardmarshall)
- Record test runtime errors [#280](https://github.com/ysugimoto/falco/pull/280) (@richardmarshall)

## v1.4.0

- Additional builtin variables [#245](https://github.com/ysugimoto/falco/pull/245) (@richardmarshall)
- Value returns from switch and bare block statements [#244](https://github.com/ysugimoto/falco/pull/244) (@richardmarshall)
- Support return value in block statement and if statement [#242](https://github.com/ysugimoto/falco/pull/242) (@ysugimoto)
- Add support for switch statements [#238](https://github.com/ysugimoto/falco/pull/238) (@richardmarshall)
- Suppress notset output [#234](https://github.com/ysugimoto/falco/pull/234) (@ysugimoto)

## v1.3.0

- Feat/state related asserter [#232](https://github.com/ysugimoto/falco/pull/232) (@ysugimoto)
- Fix not_set value related implementation [#231](https://github.com/ysugimoto/falco/pull/231) (@ysugimoto)
- Fix time default value [#230](https://gthub.com/ysugimoto/falco/pull/230) (@ysugimoto)
- Implement table manipulation testing functions [#229](https://github.com/ysugimoto/falco/pull/229) (@ysugimoto)
- User defined function fixes [@228](https://github.com/ysugimoto/falco/pull/228) (@richardmarshall)

## v1.2.1

- Fix assigning RTIME literal to RTIME variable [#226](https://github.com/ysugimoto/falco/pull/226) (@MasonM)
- Add sha1 to a set of identifiers [#224](https://github.com/ysugimoto/falco/pull/224) (@evdokimovn)
- Propagate bare returns out of nested block statements [#223](https://github.com/ysugimoto/falco/pull/223) (@richardmarshall)
- State change fixes [#221](https://github.com/ysugimoto/falco/pull/221) (@richardmarshall)
- Fix randomint(), randomint_seeded(), randombool(), and randombool_seeded() [#225](https://github.com/ysugimoto/falco/pull/225) (@MasonM)

## v1.2.0

- Allow assigning a backend to a string [#206](https://github.com/ysugimoto/falco/pull/206) (@MasonM)
- Fix testing.override_host [#207](https://github.com/ysugimoto/falco/pull/207) (@MasonM)
- Fix backend not found in director [#208](https://github.com/ysugimoto/falco/pull/208) (@MasonM)
- Fix Terraform plan parsing when multiple resources present [#209](https://github.com/ysugimoto/falco/pull/209) (@MasonM)
- Fix tester/simulator when shielding used [#210](https://github.com/ysugimoto/falco/pull/210) (@MasonM)
- Fix segfault when testing backend from snippet [#211](https://github.com/ysugimoto/falco/pull/211) (@MasonM)
- Fix calling function with ident argument [#212](https://github.com/ysugimoto/falco/pull/212) (@MasonM)
- Don't generate error for ratelimit functions [#213](https://github.com/ysugimoto/falco/pull/213) (@MasonM)
- Exit with status 1 on test failures [#214](https://github.com/ysugimoto/falco/pull/214) (@MasonM)
- Show right port number when starting simulator [#215](https://github.com/ysugimoto/falco/pull/215) (@MasonM)
- Fix boolean operator precedence [#216](https://github.com/ysugimoto/falco/pull/216) (@MasonM)
- Allow setting bereq.http.{NAME} in miss/pass [#217](https://github.com/ysugimoto/falco/pull/217) (@MasonM)
- Support "return(pass)" in vcl_fetch [#218](https://github.com/ysugimoto/falco/pull/218) (@MasonM)
- Build on linux/arm64 [#219](https://github.com/ysugimoto/falco/pull/219) (@MasonM)

## v1.1.1

- Feature/add equal fold assertion [#195](https://github.com/ysugimoto/falco/pull/195) (@ysugimoto)
- add shield director type for origin-sheileding [#197](https://github.com/ysugimoto/falco/pull/197) (@ysugimoto)
- Implement STRING to ACL regex comparison [#200](https://github.com/ysugimoto/falco/pull/200) (@MasonM)
- Fix type of client.geo.ip_override [#201](https://github.com/ysugimoto/falco/pull/201) (@MasonM)

## v1.1.0

Inspect variable on testing [#194](https://github.com/ysugimoto/falco/pull/194) (@ysugimoto)

## v1.0.1

implement testing.override_host function [#193](https://github.com/ysugimoto/falco/pull/193) (@ysugimoto)

## v1.0.0

New features for the major version.

- Local Simulator - You can run your VCL locally and test what subroutine will be processed under the some limitations
- VCL Debugger - Put breakpoint onto the VCL, and then look into what variable is set
- Unit Testing - (Experimental) unit-test for the subroutine individually, can be written by VCL

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
