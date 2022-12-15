package context

import (
	"fmt"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Reserved vcl names in Fastly
const (
	FastlyVclNameRecv    = "vcl_recv"
	FastlyVclNameHash    = "vcl_hash"
	FastlyVclNameHit     = "vcl_hit"
	FastlyVclNameMiss    = "vcl_miss"
	FastlyVclNamePass    = "vcl_pass"
	FastlyVclNameFetch   = "vcl_fetch"
	FastlyVclNameError   = "vcl_error"
	FastlyVclNameDeliver = "vcl_deliver"
	FastlyVclNameLog     = "vcl_log"
)

var fastlyReservedSubroutine = map[string]struct{}{
	FastlyVclNameRecv:    {},
	FastlyVclNameHash:    {},
	FastlyVclNameHit:     {},
	FastlyVclNameMiss:    {},
	FastlyVclNamePass:    {},
	FastlyVclNameFetch:   {},
	FastlyVclNameError:   {},
	FastlyVclNameDeliver: {},
	FastlyVclNameLog:     {},
}

var (
	defaultStaleDuration, _ = time.ParseDuration("9223372036854ms")
)

type Context struct {
	Acls                map[string]*ast.AclDeclaration
	Backends            map[string]*ast.BackendDeclaration
	Tables              map[string]*ast.TableDeclaration
	Directors           map[string]*ast.DirectorDeclaration
	Subroutines         map[string]*ast.SubroutineDeclaration
	Penaltyboxes        map[string]*ast.PenaltyboxDeclaration
	Ratecounters        map[string]*ast.RatecounterDeclaration
	Gotos               map[string]*ast.GotoStatement
	SubroutineFunctions map[string]*ast.SubroutineDeclaration

	Request         *http.Request
	BackendRequest  *http.Request
	BackendResponse *http.Response
	Object          *http.Response
	Response        *http.Response
	Scope           Scope
	RequestEndTime  time.Time

	// Interpreter states, following variables could be set in each subroutine directives
	Restarts                            int
	State                               string
	RequestHash                         *value.String
	Backend                             *value.Backend
	MaxStaleIfError                     *value.RTime
	MaxStaleWhileRevalidate             *value.RTime
	Stale                               *value.Boolean
	StaleIsError                        *value.Boolean
	StaleIsRevalidating                 *value.Boolean
	StaleContents                       *value.String
	FastlyError                         *value.String
	ClientGeoIpOverride                 *value.Boolean
	ClientSocketCongestionAlgorithm     *value.String
	ClientSocketCwnd                    *value.Integer
	ClientSocketPace                    *value.Integer
	EsiAllowInsideCData                 *value.Boolean
	EnableRangeOnPass                   *value.Boolean
	EnableSegmentedCaching              *value.Boolean
	EnableSSI                           *value.Boolean
	HashAlwaysMiss                      *value.Boolean
	HashIgnoreBusy                      *value.Boolean
	SegmentedCacheingBlockSize          *value.Integer
	ESILevel                            *value.Integer
	WafAnomalyScore                     *value.Integer
	WafBlocked                          *value.Boolean
	WafCounter                          *value.Integer
	WafExecuted                         *value.Boolean
	WafHttpViolationScore               *value.Integer
	WafInbouldAnomalyScore              *value.Integer
	WafLFIScore                         *value.Integer
	WafLogData                          *value.String
	WafLogged                           *value.Boolean
	WafMessage                          *value.String
	WafPassed                           *value.Boolean
	WafRFIScore                         *value.Integer
	WafRuleId                           *value.Integer
	WafSesionFixationScore              *value.Integer
	WafSeverity                         *value.Integer
	WafXSSScore                         *value.Integer
	BetweenBytesTimeout                 *value.RTime
	ConnectTimeout                      *value.RTime
	FirstByteTimeout                    *value.RTime
	BackendResponseGzip                 *value.Boolean
	BackendResponseBrotli               *value.Boolean
	BackendResponseCacheable            *value.Boolean
	BackendResponseDoESI                *value.Boolean
	BackendResponseDoStream             *value.Boolean
	BackendResponseGrace                *value.RTime
	BackendResponseHipaa                *value.Boolean
	BackendResponsePCI                  *value.Boolean
	BackendResponseResponse             *value.String
	BackendResponseSaintMode            *value.RTime
	BackendResponseStaleIfError         *value.RTime
	BackendResponseStaleWhileRevalidate *value.RTime
	BackendResponseStatus               *value.Integer
	BackendResponseTTL                  *value.RTime
	ObjectGrace                         *value.RTime
	ObjectTTL                           *value.RTime
	ObjectStatus                        *value.Integer
	ObjectResponse                      *value.String

	// Regex captured values like "re.group.N" and local declared variables are volatile,
	// reset this when process is outgoing for each subroutines
	RegexMatchedValues map[string]*value.String
}

func New(vcl *ast.VCL) (*Context, error) {
	ctx := &Context{
		Acls:                make(map[string]*ast.AclDeclaration),
		Backends:            make(map[string]*ast.BackendDeclaration),
		Tables:              make(map[string]*ast.TableDeclaration),
		Directors:           make(map[string]*ast.DirectorDeclaration),
		Subroutines:         make(map[string]*ast.SubroutineDeclaration),
		Penaltyboxes:        make(map[string]*ast.PenaltyboxDeclaration),
		Ratecounters:        make(map[string]*ast.RatecounterDeclaration),
		Gotos:               make(map[string]*ast.GotoStatement),
		SubroutineFunctions: make(map[string]*ast.SubroutineDeclaration),

		State:                               "NONE",
		Backend:                             nil,
		MaxStaleIfError:                     &value.RTime{Value: defaultStaleDuration},
		MaxStaleWhileRevalidate:             &value.RTime{Value: defaultStaleDuration},
		Stale:                               &value.Boolean{},
		StaleIsError:                        &value.Boolean{},
		StaleIsRevalidating:                 &value.Boolean{},
		StaleContents:                       &value.String{},
		FastlyError:                         &value.String{},
		ClientGeoIpOverride:                 &value.Boolean{},
		ClientSocketCongestionAlgorithm:     &value.String{Value: "cubic"},
		ClientSocketCwnd:                    &value.Integer{Value: 60},
		ClientSocketPace:                    &value.Integer{},
		EsiAllowInsideCData:                 &value.Boolean{},
		EnableRangeOnPass:                   &value.Boolean{},
		EnableSegmentedCaching:              &value.Boolean{},
		EnableSSI:                           &value.Boolean{},
		HashAlwaysMiss:                      &value.Boolean{},
		HashIgnoreBusy:                      &value.Boolean{},
		SegmentedCacheingBlockSize:          &value.Integer{},
		ESILevel:                            &value.Integer{},
		RequestHash:                         &value.String{},
		WafAnomalyScore:                     &value.Integer{},
		WafBlocked:                          &value.Boolean{},
		WafCounter:                          &value.Integer{},
		WafExecuted:                         &value.Boolean{},
		WafHttpViolationScore:               &value.Integer{},
		WafInbouldAnomalyScore:              &value.Integer{},
		WafLFIScore:                         &value.Integer{},
		WafLogData:                          &value.String{},
		WafLogged:                           &value.Boolean{},
		WafMessage:                          &value.String{},
		WafPassed:                           &value.Boolean{},
		WafRFIScore:                         &value.Integer{},
		WafRuleId:                           &value.Integer{},
		WafSesionFixationScore:              &value.Integer{},
		WafSeverity:                         &value.Integer{},
		WafXSSScore:                         &value.Integer{},
		BetweenBytesTimeout:                 &value.RTime{},
		ConnectTimeout:                      &value.RTime{},
		FirstByteTimeout:                    &value.RTime{Value: 15 * time.Second},
		BackendResponseGzip:                 &value.Boolean{},
		BackendResponseBrotli:               &value.Boolean{},
		BackendResponseCacheable:            &value.Boolean{},
		BackendResponseDoESI:                &value.Boolean{},
		BackendResponseDoStream:             &value.Boolean{},
		BackendResponseGrace:                &value.RTime{},
		BackendResponseHipaa:                &value.Boolean{},
		BackendResponsePCI:                  &value.Boolean{},
		BackendResponseResponse:             &value.String{},
		BackendResponseSaintMode:            &value.RTime{},
		BackendResponseStaleIfError:         &value.RTime{},
		BackendResponseStaleWhileRevalidate: &value.RTime{},
		BackendResponseStatus:               &value.Integer{},
		BackendResponseTTL:                  &value.RTime{},
		ObjectGrace:                         &value.RTime{},
		ObjectTTL:                           &value.RTime{},
		ObjectStatus:                        &value.Integer{Value: 500},
		ObjectResponse:                      &value.String{Value: "error"},

		RegexMatchedValues: make(map[string]*value.String),
	}

	for _, stmt := range vcl.Statements {
		switch t := stmt.(type) {
		case *ast.AclDeclaration:
			if _, ok := ctx.Acls[t.Name.Value]; ok {
				return nil, errors.WithStack(fmt.Errorf(
					"ACL %s is duplicated", t.Name.Value,
				))
			}
			ctx.Acls[t.Name.Value] = t
		case *ast.BackendDeclaration:
			if ctx.Backend == nil {
				ctx.Backend = &value.Backend{Value: t}
			}
			if _, ok := ctx.Backends[t.Name.Value]; ok {
				return nil, errors.WithStack(fmt.Errorf(
					"Backend %s is duplicated", t.Name.Value,
				))
			}
			ctx.Backends[t.Name.Value] = t
		case *ast.DirectorDeclaration:
			if _, ok := ctx.Directors[t.Name.Value]; ok {
				return nil, errors.WithStack(fmt.Errorf(
					"Director %s is duplicated", t.Name.Value,
				))
			}
			ctx.Directors[t.Name.Value] = t
		case *ast.TableDeclaration:
			if _, ok := ctx.Tables[t.Name.Value]; ok {
				return nil, errors.WithStack(fmt.Errorf(
					"Table %s is duplicated", t.Name.Value,
				))
			}
			ctx.Tables[t.Name.Value] = t
		case *ast.SubroutineDeclaration:
			if t.ReturnType != nil {
				if _, ok := ctx.SubroutineFunctions[t.Name.Value]; ok {
					return nil, errors.WithStack(fmt.Errorf(
						"Subroutine %s is duplicated", t.Name.Value,
					))
				}
				ctx.SubroutineFunctions[t.Name.Value] = t
				continue
			}
			exists, ok := ctx.Subroutines[t.Name.Value]
			if !ok {
				ctx.Subroutines[t.Name.Value] = t
				continue
			}

			// Duplicated fastly reserved subroutines should be concatenated
			// ref: https://developer.fastly.com/reference/vcl/subroutines/#concatenation
			if _, ok := fastlyReservedSubroutine[t.Name.Value]; ok {
				exists.Block.Statements = append(exists.Block.Statements, t.Block.Statements...)
				continue
			}
			// Other custom user subroutine could not be duplicated
			return nil, errors.WithStack(fmt.Errorf(
				"Subroutine %s is duplicated", t.Name.Value,
			))
		case *ast.PenaltyboxDeclaration:
			if _, ok := ctx.Penaltyboxes[t.Name.Value]; ok {
				return nil, errors.WithStack(fmt.Errorf(
					"Penaltybox %s is duplicated", t.Name.Value,
				))
			}
			ctx.Penaltyboxes[t.Name.Value] = t
		case *ast.RatecounterDeclaration:
			if _, ok := ctx.Ratecounters[t.Name.Value]; ok {
				return nil, errors.WithStack(fmt.Errorf(
					"Ratecounter %s is duplicated", t.Name.Value,
				))
			}
			ctx.Ratecounters[t.Name.Value] = t
		}
	}

	return ctx, nil
}
