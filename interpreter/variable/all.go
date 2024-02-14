package variable

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"path/filepath"

	"github.com/avct/uasurfer"
	"github.com/pkg/errors"
	"github.com/rs/xid"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/limitations"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Enables to access variables for all scopes
// see: https://docs.google.com/spreadsheets/d/1uV9yRdOpMQxyMm50VRBA1MDQIkcgg_cwPAgslhqatgw/edit#gid=258583317
type AllScopeVariables struct {
	Variable
	ctx *context.Context
}

func NewAllScopeVariables(ctx *context.Context) *AllScopeVariables {
	return &AllScopeVariables{
		ctx: ctx,
	}
}

// nolint: funlen,gocognit,gocyclo
func (v *AllScopeVariables) Get(s context.Scope, name string) (value.Value, error) {
	req := v.ctx.Request

	switch name {
	case BEREQ_IS_CLUSTERING:
		return &value.Boolean{Value: false}, nil
	case CLIENT_CLASS_BOT:
		ua := uasurfer.Parse(req.Header.Get("User-Agent"))
		return &value.Boolean{Value: ua.IsBot()}, nil
	case CLIENT_CLASS_BROWSER:
		ua := uasurfer.Parse(req.Header.Get("User-Agent"))
		return &value.Boolean{Value: ua.Browser.Name > 0}, nil

	// Following values are always false in interpreter
	// because they seem to be able to set in Fastly edge architecture
	// Or not be publicly its spec
	case CLIENT_CLASS_CHECKER,
		CLIENT_CLASS_DOWNLOADER,
		CLIENT_CLASS_FEEDREADER,
		CLIENT_CLASS_FILTER,
		CLIENT_CLASS_MASQUERADING,
		CLIENT_CLASS_SPAM,
		CLIENT_PLATFORM_MEDIAPLAYER,
		REQ_BACKEND_IS_SHIELD,
		REQ_IS_BACKGROUND_FETCH,
		REQ_IS_CLUSTERING,
		REQ_IS_ESI_SUBREQ,
		RESP_STALE,
		RESP_STALE_IS_ERROR,
		RESP_STALE_IS_REVALIDATING,
		WORKSPACE_OVERFLOWED:
		return &value.Boolean{Value: false}, nil

	case CLIENT_DISPLAY_TOUCHSCREEN:
		ua := uasurfer.Parse(req.Header.Get("User-Agent"))
		isTouch := ua.DeviceType == uasurfer.DevicePhone ||
			ua.DeviceType == uasurfer.DeviceTablet ||
			ua.DeviceType == uasurfer.DeviceWearable
		return &value.Boolean{Value: isTouch}, nil
	case CLIENT_PLATFORM_EREADER:
		ua := uasurfer.Parse(req.Header.Get("User-Agent"))
		return &value.Boolean{Value: ua.OS.Name == uasurfer.OSKindle}, nil
	case CLIENT_PLATFORM_GAMECONSOLE:
		ua := uasurfer.Parse(req.Header.Get("User-Agent"))
		isGame := ua.OS.Name == uasurfer.OSPlaystation ||
			ua.OS.Name == uasurfer.OSXbox ||
			ua.OS.Name == uasurfer.OSNintendo
		return &value.Boolean{Value: isGame}, nil
	case CLIENT_PLATFORM_MOBILE:
		ua := uasurfer.Parse(req.Header.Get("User-Agent"))
		return &value.Boolean{Value: ua.DeviceType == uasurfer.DevicePhone}, nil
	case CLIENT_PLATFORM_SMARTTV:
		ua := uasurfer.Parse(req.Header.Get("User-Agent"))
		return &value.Boolean{Value: ua.DeviceType == uasurfer.DeviceTV}, nil
	case CLIENT_PLATFORM_TABLET:
		ua := uasurfer.Parse(req.Header.Get("User-Agent"))
		return &value.Boolean{Value: ua.DeviceType == uasurfer.DeviceTablet}, nil
	case CLIENT_PLATFORM_TVPLAYER:
		ua := uasurfer.Parse(req.Header.Get("User-Agent"))
		return &value.Boolean{Value: ua.DeviceType == uasurfer.DeviceTV}, nil
	case CLIENT_SESS_TIMEOUT:
		return v.ctx.ClientSessTimeout, nil
	case FASTLY_INFO_EDGE_IS_TLS:
		return &value.Boolean{Value: req.TLS != nil}, nil
	case FASTLY_INFO_IS_H2:
		return &value.Boolean{Value: req.ProtoMajor == 2}, nil
	case FASTLY_INFO_IS_H3:
		return &value.Boolean{Value: req.ProtoMajor == 3}, nil
	case FASTLY_INFO_HOST_HEADER:
		return &value.String{Value: v.ctx.OriginalHost}, nil
	case FASTLY_INFO_H2_FINGERPRINT:
		if req.ProtoMajor != 2 {
			return &value.String{}, nil
		}
		// Format is undocumented, returning the value seen with the fiddle client.
		return &value.String{Value: "|00|1:0:0:16|m,s,p,a"}, nil

	// Backend is always healthy on simulator
	case REQ_BACKEND_HEALTHY:
		return &value.Boolean{Value: true}, nil

	case REQ_IS_SSL:
		return &value.Boolean{Value: req.TLS != nil}, nil
	case REQ_PROTOCOL:
		protocol := "http"
		if req.TLS != nil {
			protocol = "https"
		}
		return &value.String{Value: protocol}, nil
	case CLIENT_GEO_LATITUDE:
		return &value.Float{Value: 37.7786941}, nil
	case CLIENT_GEO_LONGITUDE:
		return &value.Float{Value: -122.3981452}, nil
	case FASTLY_ERROR:
		return &value.String{Value: ""}, nil
	case MATH_1_PI:
		return &value.Float{Value: 1 / math.Pi}, nil
	case MATH_2_PI:
		return &value.Float{Value: 2 / math.Pi}, nil
	case MATH_2_SQRTPI:
		return &value.Float{Value: 2 / math.SqrtPi}, nil
	case MATH_2PI:
		return &value.Float{Value: 2 * math.Pi}, nil
	case MATH_E:
		return &value.Float{Value: math.E}, nil
	case MATH_FLOAT_EPSILON:
		return &value.Float{Value: math.Pow(2, -52)}, nil
	case MATH_FLOAT_MAX:
		return &value.Float{Value: math.MaxFloat64}, nil
	case MATH_FLOAT_MIN:
		return &value.Float{Value: math.SmallestNonzeroFloat64}, nil
	case MATH_LN10:
		return &value.Float{Value: math.Ln10}, nil
	case MATH_LN2:
		return &value.Float{Value: math.Ln2}, nil
	case MATH_LOG10E:
		return &value.Float{Value: math.Log10E}, nil
	case MATH_LOG2E:
		return &value.Float{Value: math.Log2E}, nil
	case MATH_NAN:
		return &value.Float{IsNAN: true}, nil
	case MATH_NEG_HUGE_VAL:
		return &value.Float{IsNegativeInf: true}, nil
	case MATH_NEG_INFINITY:
		return &value.Float{IsNegativeInf: true}, nil
	case MATH_PHI:
		return &value.Float{Value: math.Phi}, nil
	case MATH_PI:
		return &value.Float{Value: math.Pi}, nil
	case MATH_PI_2:
		return &value.Float{Value: math.Pi / 2}, nil
	case MATH_PI_4:
		return &value.Float{Value: math.Pi / 4}, nil
	case MATH_POS_HUGE_VAL:
		return &value.Float{IsPositiveInf: true}, nil
	case MATH_POS_INFINITY:
		return &value.Float{IsPositiveInf: true}, nil
	case MATH_SQRT1_2:
		return &value.Float{Value: 1 / math.Sqrt2}, nil
	case MATH_SQRT2:
		return &value.Float{Value: math.Sqrt2}, nil
	case MATH_TAU:
		return &value.Float{Value: math.Pi * 2}, nil

	// AS Number always indicates "Reserved" defined by RFC7300
	// see: https://datatracker.ietf.org/doc/html/rfc7300
	case CLIENT_AS_NUMBER:
		return &value.Integer{Value: 4294967294}, nil
	case CLIENT_AS_NAME:
		return &value.String{Value: "Reserved"}, nil

	// Client display infos are unknown. Always returns -1
	case CLIENT_DISPLAY_HEIGHT,
		CLIENT_DISPLAY_PPI,
		CLIENT_DISPLAY_WIDTH:
		return &value.Integer{Value: -1}, nil

	// Client geo values always return 0
	case CLIENT_GEO_AREA_CODE,
		CLIENT_GEO_METRO_CODE,
		CLIENT_GEO_UTC_OFFSET:
		return &value.Integer{Value: 0}, nil

	// Alias of client.geo.utc_offset
	case CLIENT_GEO_GMT_OFFSET:
		return v.Get(s, "client.geo.utc_offset")

	// Client could not fully identified so returns false
	case CLIENT_IDENTIFIED:
		return &value.Boolean{Value: false}, nil

	case CLIENT_PORT:
		idx := strings.LastIndex(req.RemoteAddr, ":")
		if idx == -1 {
			return &value.Integer{Value: 0}, nil
		}
		port := req.RemoteAddr[idx+1:]
		if num, err := strconv.ParseInt(port, 10, 64); err != nil {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Failed to convert port number from string",
			))
		} else {
			return &value.Integer{Value: num}, nil
		}

	// Client requests always returns 1, means new connection is coming
	case CLIENT_REQUESTS:
		return &value.Integer{Value: 1}, nil

	// Returns tentative value because falco does not support Edge POP
	case FASTLY_FF_VISITS_THIS_POP:
		return &value.Integer{Value: 1}, nil

	// Returns common value -- do not consider of clustering
	// see: https://developer.fastly.com/reference/vcl/variables/miscellaneous/fastly-ff-visits-this-service/
	case FASTLY_FF_VISITS_THIS_SERVICE:
		switch s {
		case context.MissScope, context.HitScope, context.FetchScope:
			return &value.Integer{Value: 1}, nil
		default:
			return &value.Integer{Value: 0}, nil
		}

	// Returns tentative value -- you may know your customer_id in the contraction :-)
	case REQ_CUSTOMER_ID:
		return &value.String{Value: "FalcoVirtualCustomerId"}, nil

	// Returns fixed value which is presented on Fastly fiddle
	case MATH_FLOAT_DIG:
		return &value.Integer{Value: 15}, nil
	case MATH_FLOAT_MANT_DIG:
		return &value.Integer{Value: 53}, nil
	case MATH_FLOAT_MAX_10_EXP:
		return &value.Integer{Value: 308}, nil
	case MATH_FLOAT_MAX_EXP:
		return &value.Integer{Value: 1024}, nil
	case MATH_FLOAT_MIN_10_EXP:
		return &value.Integer{Value: -307}, nil
	case MATH_FLOAT_MIN_EXP:
		return &value.Integer{Value: -1021}, nil
	case MATH_FLOAT_RADIX:
		return &value.Integer{Value: 2}, nil
	case MATH_INTEGER_BIT:
		return &value.Integer{Value: 64}, nil
	case MATH_INTEGER_MAX:
		return &value.Integer{Value: 9223372036854775807}, nil
	case MATH_INTEGER_MIN:
		return &value.Integer{Value: -9223372036854775808}, nil

	case REQ_HEADER_BYTES_READ:
		var headerBytes int64
		// FIXME: Do we need to include total byte header LF bytes?
		for k, v := range req.Header {
			// add ":" character that header separator character
			headerBytes += int64(len(k) + 1 + len(strings.Join(v, ";")))
		}
		return &value.Integer{Value: headerBytes}, nil
	case REQ_RESTARTS:
		return &value.Integer{Value: int64(v.ctx.Restarts)}, nil

	// Returns always 1 because VCL is generated locally
	case REQ_VCL_GENERATION:
		return &value.Integer{Value: 1}, nil
	case REQ_VCL_VERSION:
		return &value.Integer{Value: 1}, nil

	case SERVER_BILLING_REGION:
		return &value.String{Value: "Asia"}, nil // always returns Asia
	case SERVER_PORT:
		return &value.Integer{Value: int64(3124)}, nil // fixed server port number
	case SERVER_POP:
		return &value.String{Value: "FALCO"}, nil // Intend to set string not exists in Fastly POP certainly

	// workspace related values respects Fastly fiddle one
	case WORKSPACE_BYTES_FREE:
		return &value.Integer{Value: 125008}, nil
	case WORKSPACE_BYTES_TOTAL:
		return &value.Integer{Value: 139392}, nil

	// backend.src_ip always incicates this server, means localhost
	case BERESP_BACKEND_SRC_IP:
		return &value.IP{Value: net.IPv4(127, 0, 0, 1)}, nil
	case SERVER_IP:
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return value.Null, errors.WithStack(err)
		}
		var addr net.IP
		for _, a := range addrs {
			if ip, ok := a.(*net.IPNet); !ok {
				continue
			} else if ip.IP.IsLoopback() {
				continue
			} else if ip.IP.To4() != nil || ip.IP.To16() != nil {
				addr = ip.IP
				break
			}
		}
		if addr == nil {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Failed to get local server IP address",
			))
		}
		return &value.IP{Value: addr}, nil

	case REQ_BACKEND:
		return &value.Backend{Value: v.ctx.Backend.Value, Director: v.ctx.Backend.Director}, nil
	case REQ_GRACE:
		return v.Get(s, "req.max_stale_if_error")

	// Return current state
	case REQ_MAX_STALE_IF_ERROR:
		return v.ctx.MaxStaleIfError, nil
	case REQ_MAX_STALE_WHILE_REVALIDATE:
		return v.ctx.MaxStaleWhileRevalidate, nil

	case TIME_ELAPSED:
		return &value.RTime{Value: time.Since(v.ctx.RequestStartTime)}, nil
	case CLIENT_BOT_NAME:
		ua := uasurfer.Parse(req.Header.Get("User-Agent"))
		if !ua.IsBot() {
			return &value.String{Value: ""}, nil
		}
		return &value.String{Value: ua.Browser.Name.String()}, nil
	case CLIENT_BROWSER_NAME:
		ua := uasurfer.Parse(req.Header.Get("User-Agent"))
		return &value.String{Value: ua.Browser.Name.String()}, nil
	case CLIENT_BROWSER_VERSION:
		ua := uasurfer.Parse(req.Header.Get("User-Agent"))
		v := ua.Browser.Version
		return &value.String{
			Value: fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch),
		}, nil

	// TODO: respect artbitrary request
	case CLIENT_GEO_CITY,
		CLIENT_GEO_CITY_ASCII,
		CLIENT_GEO_CITY_LATIN1,
		CLIENT_GEO_CITY_UTF8,
		CLIENT_GEO_CONN_SPEED,
		CLIENT_GEO_CONN_TYPE,
		CLIENT_GEO_CONTINENT_CODE,
		CLIENT_GEO_COUNTRY_CODE,
		CLIENT_GEO_COUNTRY_CODE3,
		CLIENT_GEO_COUNTRY_NAME,
		CLIENT_GEO_COUNTRY_NAME_ASCII,
		CLIENT_GEO_COUNTRY_NAME_LATIN1,
		CLIENT_GEO_COUNTRY_NAME_UTF8,
		CLIENT_GEO_IP_OVERRIDE,
		CLIENT_GEO_POSTAL_CODE,
		CLIENT_GEO_PROXY_DESCRIPTION,
		CLIENT_GEO_PROXY_TYPE,
		CLIENT_GEO_REGION,
		CLIENT_GEO_REGION_ASCII,
		CLIENT_GEO_REGION_LATIN1,
		CLIENT_GEO_REGION_UTF8:
		return &value.String{Value: "unknown"}, nil

	case CLIENT_IDENTITY:
		if v.ctx.ClientIdentity == nil {
			// default as client.ip
			idx := strings.LastIndex(req.RemoteAddr, ":")
			if idx == -1 {
				return &value.String{Value: req.RemoteAddr}, nil
			}
			return &value.String{Value: req.RemoteAddr[:idx]}, nil
		}
		return v.ctx.ClientIdentity, nil

	case CLIENT_IP:
		idx := strings.LastIndex(req.RemoteAddr, ":")
		if idx == -1 {
			return &value.IP{Value: net.ParseIP(req.RemoteAddr)}, nil
		}
		return &value.IP{Value: net.ParseIP(req.RemoteAddr[:idx])}, nil

	case CLIENT_OS_NAME:
		ua := uasurfer.Parse(req.Header.Get("User-Agent"))
		return &value.String{Value: ua.OS.Name.String()}, nil
	case CLIENT_OS_VERSION:
		ua := uasurfer.Parse(req.Header.Get("User-Agent"))
		v := ua.OS.Version
		return &value.String{
			Value: fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch),
		}, nil

	// Always empty string
	case CLIENT_PLATFORM_HWTYPE:
		return &value.String{Value: ""}, nil

	case FASTLY_INFO_STATE:
		return &value.String{Value: v.ctx.State}, nil
	case LF:
		return &value.String{Value: "\n"}, nil
	case NOW_SEC:
		// For testing - if fixed time is injected, return it
		if v.ctx.FixedTime != nil {
			return &value.String{Value: fmt.Sprint(v.ctx.FixedTime.Unix())}, nil
		}
		return &value.String{Value: fmt.Sprint(time.Now().Unix())}, nil
	case REQ_BODY:
		switch req.Method {
		case http.MethodPatch, http.MethodPost, http.MethodPut:
			var b bytes.Buffer
			if _, err := b.ReadFrom(req.Body); err != nil {
				return value.Null, errors.WithStack(fmt.Errorf(
					"Could not read request body",
				))
			}
			req.Body = io.NopCloser(bytes.NewReader(b.Bytes()))
			// size is limited to 8KB
			if len(b.Bytes()) > 1024*8 {
				return value.Null, errors.WithStack(fmt.Errorf(
					"Request body is limited to 8KB",
				))
			}
			return &value.String{Value: b.String()}, nil
		default:
			return &value.String{Value: ""}, nil
		}
	case REQ_BODY_BASE64:
		switch req.Method {
		case http.MethodPatch, http.MethodPost, http.MethodPut:
			var b bytes.Buffer
			if _, err := b.ReadFrom(req.Body); err != nil {
				return value.Null, errors.WithStack(fmt.Errorf(
					"Could not read request body",
				))
			}
			req.Body = io.NopCloser(bytes.NewReader(b.Bytes()))
			// size is limited to 8KB
			if len(b.Bytes()) > 1024*8 {
				return value.Null, errors.WithStack(fmt.Errorf(
					"Request body is limited to 8KB",
				))
			}
			return &value.String{
				Value: base64.StdEncoding.EncodeToString(b.Bytes()),
			}, nil
		default:
			return &value.String{Value: ""}, nil
		}
	case REQ_DIGEST:
		if v.ctx.RequestHash.Value == "" {
			return &value.String{
				Value: strings.Repeat("0", 64),
			}, nil
		}
		// Simply we generate hash with sha256 because hashing algorithm is undocumented (or maybe secret)
		// But it seems to be upper case hex string
		return &value.String{
			Value: strings.ToUpper(
				fmt.Sprintf("%x", sha256.Sum256([]byte(v.ctx.RequestHash.Value))),
			),
		}, nil
	case REQ_METHOD:
		return &value.String{Value: req.Method}, nil
	case REQ_POSTBODY:
		return v.Get(s, "req.body")
	case REQ_PROTO:
		return &value.String{Value: req.Proto}, nil
	case REQ_REQUEST:
		return v.Get(s, "req.method")
	case REQ_SERVICE_ID:
		id := os.Getenv("FASYLY_SERVICE_ID")
		if id == "" {
			id = FALCO_VIRTUAL_SERVICE_ID
		}
		return &value.String{Value: id}, nil
	case REQ_TOPURL: // FIXME: what is the difference of req.url ?
		u := req.URL.EscapedPath()
		if v := req.URL.RawQuery; v != "" {
			u += "?" + v
		}
		if v := req.URL.RawFragment; v != "" {
			u += "#" + v
		}
		return &value.String{Value: u}, nil
	case REQ_URL:
		u := req.URL.EscapedPath()
		if v := req.URL.RawQuery; v != "" {
			u += "?" + v
		}
		if v := req.URL.RawFragment; v != "" {
			u += "#" + v
		}
		return &value.String{Value: u}, nil
	case REQ_URL_BASENAME:
		return &value.String{
			Value: filepath.Base(req.URL.Path),
		}, nil
	case REQ_URL_DIRNAME:
		return &value.String{
			Value: filepath.Dir(req.URL.Path),
		}, nil
	case REQ_URL_EXT:
		ext := filepath.Ext(req.URL.Path)
		return &value.String{
			Value: strings.TrimPrefix(ext, "."),
		}, nil
	case REQ_URL_PATH:
		return &value.String{Value: req.URL.EscapedPath()}, nil
	case REQ_URL_QS:
		return &value.String{Value: req.URL.RawQuery}, nil
	case REQ_VCL:
		id := os.Getenv("FASYLY_SERVICE_ID")
		if id == "" {
			id = FALCO_VIRTUAL_SERVICE_ID
		}
		return &value.String{
			Value: fmt.Sprintf("%s.%d_%d-%s", id, 1, 0, strings.Repeat("0", 32)),
		}, nil
	case REQ_VCL_MD5:
		id := os.Getenv("FASYLY_SERVICE_ID")
		if id == "" {
			id = FALCO_VIRTUAL_SERVICE_ID
		}
		vcl := fmt.Sprintf("%s.%d_%d-%s", id, 1, 0, strings.Repeat("0", 32))
		return &value.String{
			Value: fmt.Sprintf("%x", md5.Sum([]byte(vcl))),
		}, nil
	case REQ_XID:
		return &value.String{Value: xid.New().String()}, nil

	// Fixed values
	case SERVER_DATACENTER:
		return &value.String{Value: "FALCO"}, nil
	case SERVER_HOSTNAME:
		return &value.String{Value: "cache-localsimulator"}, nil
	case SERVER_IDENTITY:
		return &value.String{Value: "cache-localsimulator"}, nil
	case SERVER_REGION:
		return &value.String{Value: "US"}, nil
	case STALE_EXISTS:
		return v.ctx.StaleContents, nil
	case TIME_ELAPSED_MSEC:
		return &value.String{
			Value: fmt.Sprint(time.Since(v.ctx.RequestStartTime).Milliseconds()),
		}, nil
	case TIME_ELAPSED_MSEC_FRAC:
		return &value.String{
			Value: fmt.Sprintf("%03d", time.Since(v.ctx.RequestStartTime).Milliseconds()),
		}, nil
	case TIME_ELAPSED_SEC:
		return &value.String{
			Value: fmt.Sprint(int64(time.Since(v.ctx.RequestStartTime).Seconds())),
		}, nil
	case TIME_ELAPSED_USEC:
		return &value.String{
			Value: fmt.Sprint(time.Since(v.ctx.RequestStartTime).Microseconds()),
		}, nil
	case TIME_ELAPSED_USEC_FRAC:
		return &value.String{
			Value: fmt.Sprintf("%06d", time.Since(v.ctx.RequestStartTime).Microseconds()),
		}, nil
	case TIME_START_MSEC:
		return &value.String{
			Value: fmt.Sprint(v.ctx.RequestStartTime.UnixMilli()),
		}, nil
	case TIME_START_MSEC_FRAC:
		return &value.String{
			Value: fmt.Sprint(v.ctx.RequestStartTime.UnixMilli() % 1000),
		}, nil
	case TIME_START_SEC:
		return &value.String{
			Value: fmt.Sprint(v.ctx.RequestStartTime.Unix()),
		}, nil
	case TIME_START_USEC:
		return &value.String{
			Value: fmt.Sprint(v.ctx.RequestStartTime.UnixMicro()),
		}, nil
	case TIME_START_USEC_FRAC:
		return &value.String{
			Value: fmt.Sprint(v.ctx.RequestStartTime.UnixMicro() % 1000000),
		}, nil
	case NOW:
		// For testing - if fixed time is injected, return it
		if v.ctx.FixedTime != nil {
			return &value.Time{Value: *v.ctx.FixedTime}, nil
		}
		return &value.Time{Value: time.Now()}, nil
	case TIME_START:
		return &value.Time{Value: v.ctx.RequestStartTime}, nil
	}

	if val := v.getFromRegex(name); val != nil {
		return val, nil
	}

	if injectedVariable != nil {
		if val, err := injectedVariable.Get(v.ctx, s, name); err == nil {
			return val, nil
		}
	}

	return value.Null, errors.WithStack(fmt.Errorf(
		"Undefined variable %s", name,
	))
}

func (v *AllScopeVariables) getFromRegex(name string) value.Value {
	// regex captured variables matching
	if match := regexMatchedRegex.FindStringSubmatch(name); match != nil {
		if val, ok := v.ctx.RegexMatchedValues[match[1]]; ok {
			return val
		}
	}

	// HTTP request header matching
	if match := requestHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		return getRequestHeaderValue(v.ctx.Request, match[1])
	}

	// Ratecounter variable matching
	if match := rateCounterRegex.FindStringSubmatch(name); match != nil {
		var val float64
		// all ratecounter variable value returns 1.0 fixed value
		switch match[1] {
		case "rate_10s",
			"rate_1s",
			"rate.60s",
			"bucket.10s",
			"bucket.20s",
			"bucket.30s",
			"bucket.40s",
			"bucket.50s",
			"bucket.60s":
			val = 1.0
		}
		return &value.Float{
			Value: val,
		}
	}
	return nil
}

func (v *AllScopeVariables) Set(s context.Scope, name, operator string, val value.Value) error {
	switch strings.ToLower(name) {
	case CLIENT_IDENTITY:
		if v.ctx.ClientIdentity == nil {
			v.ctx.ClientIdentity = &value.String{Value: ""}
		}
		if err := doAssign(v.ctx.ClientIdentity, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case CLIENT_SESS_TIMEOUT:
		if err := doAssign(v.ctx.ClientSessTimeout, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case RESP_STALE:
		if err := doAssign(v.ctx.Stale, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case RESP_STALE_IS_ERROR:
		if err := doAssign(v.ctx.StaleIsError, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case RESP_STALE_IS_REVALIDATING:
		if err := doAssign(v.ctx.StaleIsRevalidating, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case REQ_BACKEND:
		if err := doAssign(v.ctx.Backend, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case REQ_GRACE:
		return v.Set(s, "req.max_stale_if_error", operator, val)
	case REQ_MAX_STALE_IF_ERROR:
		if err := doAssign(v.ctx.MaxStaleIfError, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case REQ_MAX_STALE_WHILE_REVALIDATE:
		if err := doAssign(v.ctx.MaxStaleWhileRevalidate, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case CLIENT_GEO_IP_OVERRIDE:
		if err := doAssign(v.ctx.ClientGeoIpOverride, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case REQ_METHOD:
		left := &value.String{Value: v.ctx.Request.Method}
		if err := doAssign(left, operator, val); err != nil {
			return errors.WithStack(err)
		}
		v.ctx.Request.Method = left.Value
		return nil
	case REQ_REQUEST:
		return v.Set(s, "req.method", operator, val)
	case REQ_URL:
		u := v.ctx.Request.URL.Path
		if query := v.ctx.Request.URL.RawQuery; query != "" {
			u += "?" + query
		}
		if fragment := v.ctx.Request.URL.RawFragment; fragment != "" {
			u += "#" + fragment
		}
		left := &value.String{Value: u}
		if err := doAssign(left, operator, val); err != nil {
			return errors.WithStack(err)
		}
		parsed, err := url.Parse(left.Value)
		if err != nil {
			return errors.WithStack(err)
		}
		// Update request URLs
		v.ctx.Request.URL.RawPath = parsed.EscapedPath()
		v.ctx.Request.URL.RawQuery = parsed.RawQuery
		v.ctx.Request.URL.RawFragment = parsed.RawFragment
		return nil
	}

	if match := requestHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		if err := limitations.CheckProtectedHeader(match[1]); err != nil {
			return errors.WithStack(err)
		}
		if v, ok := val.(*value.Backend); ok && v.Literal {
			return errors.WithStack(fmt.Errorf(
				"BACKEND literal %s cannot be assigned to %s in scope: %s", v.String(), name, s.String(),
			))
		}
		setRequestHeaderValue(v.ctx.Request, match[1], val)
		return nil
	}

	if injectedVariable != nil {
		if err := injectedVariable.Set(v.ctx, s, name, operator, val); err == nil {
			return nil
		}
	}

	return errors.WithStack(fmt.Errorf(
		"Variable %s is not found or could not set in scope: %s", name, s.String(),
	))
}

func (v *AllScopeVariables) Add(s context.Scope, name string, val value.Value) error {
	// Add statement could be use only for HTTP header
	match := requestHttpHeaderRegex.FindStringSubmatch(name)
	if match == nil {
		return errors.WithStack(fmt.Errorf(
			"Variable %s is not found or could not add. Normally add statement could use for HTTP header", name,
		))
	}
	if err := limitations.CheckProtectedHeader(match[1]); err != nil {
		return errors.WithStack(err)
	}

	v.ctx.Request.Header.Add(match[1], val.String())
	return nil
}

func (v *AllScopeVariables) Unset(s context.Scope, name string) error {
	if name == "fastly.error" {
		v.ctx.FastlyError.Value = ""
		return nil
	}
	match := requestHttpHeaderRegex.FindStringSubmatch(name)
	if match == nil {
		return errors.WithStack(fmt.Errorf(
			"Variable %s is not found or could not unset", name,
		))
	}
	if err := limitations.CheckProtectedHeader(match[1]); err != nil {
		return errors.WithStack(err)
	}

	unsetRequestHeaderValue(v.ctx.Request, match[1])
	return nil
}

var _ Variable = &AllScopeVariables{}
