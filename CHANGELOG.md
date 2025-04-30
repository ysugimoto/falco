## v1.15.3

- Tweak vendor detecting tests [#437](https://github.com/ysugimoto/falco/pull/437) (@ysugimoto)
- Implement new predefined variables [#436](https://github.com/ysugimoto/falco/pull/436) (@ysugimoto)
- Add VCL_ prefix at scope string in test result printing [#435](https://github.com/ysugimoto/falco/pull/435) (@ysugimoto)

## v1.15.2

- Pin GHA action version  [#426](https://github.com/ysugimoto/falco/pull/426) (@ysugimoto)
- Implement new predefined variables [#428](https://github.com/ysugimoto/falco/pull/428) (@ysugimoto)
- Implement `fastly.ddos_detected` predefined variables [#430](https://github.com/ysugimoto/falco/pull/430) (@ysugimoto)
- Fix base64 decode function with single equal characters [#432](https://github.com/ysugimoto/falco/pull/432) (@ysugimoto)

## v1.15.1

-  Improve digest.ecdsa_verify function [#425](https://github.com/ysugimoto/falco/pull/425) (@ysugimoto)
-  Fix/multiline expressions [#424](https://github.com/ysugimoto/falco/pull/424) (@ysugimoto)

## v1.15.0

-  Implement max call stack for calling subroutine recursively [#423](https://github.com/ysugimoto/falco/pull/423) (@ysugimoto)
-  fix: resolve missing default transport settings in HTTPS by cloning http.DefaultTransport [#422](https://github.com/ysugimoto/falco/pull/422) (@3846masa)
-  Improve set statement value expression [#420](https://github.com/ysugimoto/falco/pull/420) (@ysugimoto)
-  Implement digest.ecdsa_verify function[#419](https://github.com/ysugimoto/falco/pull/419) (@ysugimoto)

## v1.14.0

- use pcre regexp for assetion function [#416](https://github.com/ysugimoto/falco/pull/416) (@ysugimoto)
- Display coverage table [#415](https://github.com/ysugimoto/falco/pull/415) (@ysugimoto)
- Implement test coverage measurement [#414](https://github.com/ysugimoto/falco/pull/414) (@ysugimoto)
- Improve and new feature for parser package [#413](https://github.com/ysugimoto/falco/pull/413) (@ysugimoto)
- Reset regex captured group when matched [#412](https://github.com/ysugimoto/falco/pull/412) (@ysugimoto)
- remove goling linter-settings [#411](https://github.com/ysugimoto/falco/pull/411) (@ysugimoto)
- fix objective header set like foo:bar [#410](https://github.com/ysugimoto/falco/pull/410) (@ysugimoto)
- use pcre regular expression in interpreter [#409](https://github.com/ysugimoto/falco/pull/409) (@ysugimoto)

## v1.13.0

- list all configuration fields [#406](https://github.com/ysugimoto/falco/pull/406) (@ysugimoto)
- implement edge dictionary injectable for testing process [#405](https://github.com/ysugimoto/falco/pull/405) (@ysugimoto)
- implement assert.not_state assertion function [#403](https://github.com/ysugimoto/falco/pull/403) (@ysugimoto)
- update golang 1.23.5 and golangci-lint v1.63, fix new reports [#402](https://github.com/ysugimoto/falco/pull/402) (@ysugimoto)
- refactor linter context package [#401](https://github.com/ysugimoto/falco/pull/401) (@ysugimoto)
- Fix scheduler action [#396](https://github.com/ysugimoto/falco/pull/396) (@ysugimoto)

## v1.12.0

- Add more logic and error definition for long string parsing [#394](https://github.com/ysugimoto/falco/pull/394) (@ysugimoto)
- fix: formatting is broken if using elseif or elsif [#393](https://github.com/ysugimoto/falco/pull/393) (@ronnnnn)
- fix: support --version option [#392](https://github.com/ysugimoto/falco/pull/392) (@ronnnnn)
- Add TIME type support for conditional operators to interpreter [#390](https://github.com/ysugimoto/falco/pull/390) (@Co9xs)
- Update falco simulate command in README [#389](https://github.com/ysugimoto/falco/pull/389) (@TakeshiOnishi)
- Write formatter configuration in docs [#388](https://github.com/ysugimoto/falco/pull/388) (@ysugimoto)
- Fix header subfield handling [#385](https://github.com/ysugimoto/falco/pull/385) (@gabrielg)
- Allows subroutine calls in return statements [#384](https://github.com/ysugimoto/falco/pull/384) (@gabrielg)
- Allow access to body set bu synthetic in tests [#382](https://github.com/ysugimoto/falco/pull/382) (@gabrielg)
- Change fastly.error from FLOAT to STRING [#380](https://github.com/ysugimoto/falco/pull/380) (@gabrielg)
- Add support for long strings with heredoc delimiters [#379](https://github.com/ysugimoto/falco/pull/379) (@gabrielg)
- Implement scheduler for documentation-check [#377](https://github.com/ysugimoto/falco/pull/377) (@ysugimoto)
- Fix grouped testing syntax [#376](https://github.com/ysugimoto/falco/pull/376) (@bungoume)
- Fix fastly services recursively in terraform planned JSON [#375](https://github.com/ysugimoto/falco/pull/375) (@ysugimoto)
- Lint custom statement [#374](https://github.com/ysugimoto/falco/pull/374) (@ysugimoto)
- Lexer performance improvement [#372](https://github.com/ysugimoto/falco/pull/372) (@ysugimoto)
- Benchmark Performance [#371](https://github.com/ysugimoto/falco/pull/371) (@ysugimoto)

## v1.11.2

- fix string concatenation problem for functioncall and if expression [#369](https://github.com/ysugimoto/falco/pull/369) (@ysugimoto)

## v1.11.1

- add assert.not_error function to function table [#368](https://github.com/ysugimoto/falco/pull/368) (@ysugimoto)

## v1.11.0

- add dap subcommand and support basic DAP features [#349](https://github.com/ysugimoto/falco/pull/349) (@rinx)
- Fix tiny bug of base64 decode functions [#351](https://github.com/ysugimoto/falco/pull/351) (@ysugimoto)
- implement `assert.not_error` assertion method [#352](https://github.com/ysugimoto/falco/pull/352) (@ysugimoto)
- fix header existence logic, exactly treat as null or empty string [#353](https://github.com/ysugimoto/falco/pull/353) (@ysugimoto)
- improve url encode and decode built-in functions [#354](https://github.com/ysugimoto/falco/pull/354) (@ysugimoto)
- move base64 related logic to shared codec [#355](https://github.com/ysugimoto/falco/pull/355) (@ysugimoto)
- Fix hex display: pad 01-0F values to two digits [#356](https://github.com/ysugimoto/falco/pull/356) (@bungoume)
- fix literal comparing issue for injected variables [#357](https://github.com/ysugimoto/falco/pull/357) (@ysugimoto)
- add `bereq.max_reuse_idle_time` variable support [#362](https://github.com/ysugimoto/falco/pull/362) (@ysugimoto)
- add remote director resource to lint [#363](https://github.com/ysugimoto/falco/pull/363) (@ysugimoto)
- Improve string concatenation logic [#364](https://github.com/ysugimoto/falco/pull/364) (@ysugimoto)
- implement raising deprecated error [#366](https://github.com/ysugimoto/falco/pull/366) (@ysugimoto)
- docs(dap): add a brief documentation about dap subcommand [#367](https://github.com/ysugimoto/falco/pull/367) (@rinx)

## v1.10.0

- add watch option for incremental testing [#347](https://github.com/ysugimoto/falco/pull/347) (@ysugimoto)
- exact custom token [#346](https://github.com/ysugimoto/falco/pull/346) (@ysugimoto)
- implement uuid version7 related new functions [#345](https://github.com/ysugimoto/falco/pull/345) (@ysugimoto)
- inject value for tentative in simulator [#344](https://github.com/ysugimoto/falco/pull/344) (@ysugimoto)
- correct typo in SortDeclaration default tag [#342](https://github.com/ysugimoto/falco/pull/342) (@acme)
- adjust default TrailingCommentWidth to 1 [#341](https://github.com/ysugimoto/falco/pull/341) (@acme)
- update timezone in test [#340](https://github.com/ysugimoto/falco/pull/340) (@acme)
- add `--genearted` option and add vcl_pipe related linter rule [#339](https://github.com/ysugimoto/falco/pull/339) (@ysugimoto)
- support Fastly generated specific syntaxes [#338](https://github.com/ysugimoto/falco/pull/338) (@ysugimoto)

## v1.9.1

- strict macro linting [#336](https://github.com/ysugimoto/falco/pull/336) (@ysugimoto)
- feat(formatter): prevent indentation of #FASTLY macros [#335](https://github.com/ysugimoto/falco/pull/335) (@acme)
- fix(formatter): remove space between return and parenthesis [#334](https://github.com/ysugimoto/falco/pull/334) (@acme)
- Add feature to disable only specific lint rules with ignore comment [#333](https://github.com/ysugimoto/falco/pull/333) (@nodaguti)
- Set exit code to 1 when there are one or more lint errors [#332](https://github.com/ysugimoto/falco/pull/332) (@nodaguti)
- Add extra format check for backend.share_key [#331](https://github.com/ysugimoto/falco/pull/331) (@nodaguti)
- Fix broken result message of tester and use exactly the same format for both passed and failed tests [#330](https://github.com/ysugimoto/falco/pull/330) (@nodaguti)

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
