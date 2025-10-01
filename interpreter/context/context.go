package context

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/interpreter/cache"
	"github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/resolver"
	"github.com/ysugimoto/falco/snippet"
	"github.com/ysugimoto/falco/tester/shared"
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

var FastlyReservedSubroutine = map[string]string{
	FastlyVclNameRecv:    "recv",
	FastlyVclNameHash:    "hash",
	FastlyVclNameHit:     "hit",
	FastlyVclNameMiss:    "miss",
	FastlyVclNamePass:    "pass",
	FastlyVclNameFetch:   "fetch",
	FastlyVclNameError:   "error",
	FastlyVclNameDeliver: "deliver",
	FastlyVclNameLog:     "log",
}

var (
	defaultStaleDuration, _ = time.ParseDuration("9223372036854ms") // nolint: errcheck
)

type Context struct {
	TLSServer           bool
	Resolver            resolver.Resolver
	FastlySnippets      *snippet.Snippets
	Acls                map[string]*value.Acl
	Backends            map[string]*value.Backend
	Tables              map[string]*ast.TableDeclaration
	Subroutines         map[string]*ast.SubroutineDeclaration
	Penaltyboxes        map[string]*value.Penaltybox
	Ratecounters        map[string]*value.Ratecounter
	Gotos               map[string]*ast.GotoStatement
	SubroutineFunctions map[string]*ast.SubroutineDeclaration
	OriginalHost        string
	IsActualResponse    bool

	OverrideMaxBackends    int
	OverrideMaxAcls        int
	OverrideRequest        *config.RequestConfig
	OverrideBackends       map[string]*config.OverrideBackend
	InjectEdgeDictionaries map[string]config.EdgeDictionary

	// Mocking subroutines map
	MockedSubroutines            map[string]*ast.SubroutineDeclaration
	MockedFunctioncalSubroutines map[string]*ast.SubroutineDeclaration

	Request          *http.Request
	BackendRequest   *http.Request
	BackendResponse  *http.Response
	Object           *http.Response
	Response         *http.Response
	Scope            Scope
	RequestEndTime   time.Time
	RequestStartTime time.Time
	CacheHitItem     *cache.CacheItem

	// Interpreter states, following variables could be set in each subroutine directives
	Restarts                            int
	State                               string
	RequestHash                         *value.String
	RequestID                           *value.String
	Backend                             *value.Backend
	MaxStaleIfError                     *value.RTime
	MaxStaleWhileRevalidate             *value.RTime
	Stale                               *value.Boolean
	StaleIsError                        *value.Boolean
	StaleIsRevalidating                 *value.Boolean
	StaleContents                       *value.String
	FastlyError                         *value.String
	ClientIdentity                      *value.String
	ClientGeoIpOverride                 *value.String
	ClientSocketCongestionAlgorithm     *value.String
	ClientSocketCwnd                    *value.Integer
	ClientSocketPace                    *value.Integer
	ClientSessTimeout                   *value.RTime
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
	WafInboundAnomalyScore              *value.Integer
	WafLFIScore                         *value.Integer
	WafLogData                          *value.String
	WafLogged                           *value.Boolean
	WafMessage                          *value.String
	WafPassed                           *value.Boolean
	WafPHPInjectionScore                *value.Integer
	WafRCEScore                         *value.Integer
	WafRFIScore                         *value.Integer
	WafRuleId                           *value.Integer
	WafSessionFixationScore             *value.Integer
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
	IsLocallyGenerated                  *value.Boolean
	BackendRequestMaxReuseIdleTime      *value.RTime

	// For testing fields
	// Stored subroutine return state
	ReturnState *value.String
	// Injected fixed time for `now`, `now.sec`, etc
	FixedTime *time.Time
	// Count of subroutine called
	SubroutineCalls map[string]int
	// Injected fixed access rate
	FixedAccessRate *float64

	// Coverage marker pointer. not nil if testing with coverage measurement
	Coverage *shared.Coverage

	// Regex captured values like "re.group.N" and local declared variables are volatile,
	// reset this when process is outgoing for each subroutines
	RegexMatchedValues map[string]*value.String

	// Modify states from builtin functions
	DisableCompressionHeaders []string // modified via "h2.disable_header_compression"
	PushResources             []string // modified via "h2.push"
	H3AltSvc                  bool     // modified via "h3.alt_svc"

	// Marker that ESI is triggered. This field will be changed when esi statement is present.
	// However, Fastly document says the esi will be triggered when esi statement is executed in FETCH directive.
	// see: https://developer.fastly.com/reference/vcl/statements/esi/
	TriggerESI bool

	// Marker that return status is called.
	// This field is used for ensuring some state machine subroutine returns new state via return statement.
	// For example, FSATLYPURGE method must return the next state by calling return statement.
	ReturnStatementCalled bool

	// Marker that return request is purge request.
	IsPurgeRequest bool

	// Flag for a synthetic response has been set.
	// It means that some VCL will set response phase like `set obj.response = "xxx"`
	// but we should ignore when synthetic response has already set.
	// Note that obj.response is deprecated after HTTP/1.1 but VCL still supports this spec.
	HasSyntheticResponse bool

	OverrideVariables map[string]value.Value
}

func New(options ...Option) *Context {
	ctx := &Context{
		Acls:                   make(map[string]*value.Acl),
		Backends:               make(map[string]*value.Backend),
		Tables:                 make(map[string]*ast.TableDeclaration),
		Subroutines:            make(map[string]*ast.SubroutineDeclaration),
		Penaltyboxes:           make(map[string]*value.Penaltybox),
		Ratecounters:           make(map[string]*value.Ratecounter),
		Gotos:                  make(map[string]*ast.GotoStatement),
		SubroutineFunctions:    make(map[string]*ast.SubroutineDeclaration),
		OverrideBackends:       make(map[string]*config.OverrideBackend),
		InjectEdgeDictionaries: make(map[string]config.EdgeDictionary),

		MockedSubroutines:            make(map[string]*ast.SubroutineDeclaration),
		MockedFunctioncalSubroutines: make(map[string]*ast.SubroutineDeclaration),

		CacheHitItem:                    nil,
		RequestStartTime:                time.Now(),
		State:                           "NONE",
		Backend:                         nil,
		ClientIdentity:                  nil,
		MaxStaleIfError:                 &value.RTime{Value: defaultStaleDuration},
		MaxStaleWhileRevalidate:         &value.RTime{Value: defaultStaleDuration},
		Stale:                           &value.Boolean{},
		StaleIsError:                    &value.Boolean{},
		StaleIsRevalidating:             &value.Boolean{},
		StaleContents:                   &value.String{},
		FastlyError:                     &value.String{},
		ClientGeoIpOverride:             &value.String{},
		ClientSocketCongestionAlgorithm: &value.String{Value: "cubic"},
		ClientSocketCwnd:                &value.Integer{Value: 60},
		ClientSocketPace:                &value.Integer{},
		ClientSessTimeout:               &value.RTime{Value: time.Minute * 10},
		EsiAllowInsideCData:             &value.Boolean{},
		EnableRangeOnPass:               &value.Boolean{},
		EnableSegmentedCaching:          &value.Boolean{},
		EnableSSI:                       &value.Boolean{},
		HashAlwaysMiss:                  &value.Boolean{},
		HashIgnoreBusy:                  &value.Boolean{},
		SegmentedCacheingBlockSize:      &value.Integer{},
		ESILevel:                        &value.Integer{},
		RequestHash:                     &value.String{},

		// The format of the request ID is not documented.
		// Observations indicate that it is a zero padded hex representation of two
		// 64-bit values The first 64-bits are seemingly random, the nature of the
		// apparent randomness is unknown. The second 64-bit value is always 1.
		RequestID: &value.String{Value: fmt.Sprintf("%016x0000000000000001", rand.Int63())},

		WafAnomalyScore:                     &value.Integer{},
		WafBlocked:                          &value.Boolean{},
		WafCounter:                          &value.Integer{},
		WafExecuted:                         &value.Boolean{},
		WafHttpViolationScore:               &value.Integer{},
		WafInboundAnomalyScore:              &value.Integer{},
		WafLFIScore:                         &value.Integer{},
		WafLogData:                          &value.String{},
		WafLogged:                           &value.Boolean{},
		WafMessage:                          &value.String{},
		WafPassed:                           &value.Boolean{},
		WafPHPInjectionScore:                &value.Integer{},
		WafRCEScore:                         &value.Integer{},
		WafRFIScore:                         &value.Integer{},
		WafRuleId:                           &value.Integer{},
		WafSessionFixationScore:             &value.Integer{},
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
		ObjectResponse:                      &value.String{IsNotSet: true},
		ReturnState:                         &value.String{IsNotSet: true},
		IsLocallyGenerated:                  &value.Boolean{},
		BackendRequestMaxReuseIdleTime:      &value.RTime{},

		RegexMatchedValues: make(map[string]*value.String),
		SubroutineCalls:    make(map[string]int),

		OverrideVariables: make(map[string]value.Value),
	}

	// collect options
	for i := range options {
		options[i](ctx)
	}

	return ctx
}
