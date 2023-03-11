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
	ua := uasurfer.Parse(req.Header.Get("User-Agent"))

	switch name {
	case "bereq.is_clustering":
		return &value.Boolean{Value: false}, nil
	case "client.class.bot":
		return &value.Boolean{Value: ua.IsBot()}, nil
	case "client.class.browser":
		return &value.Boolean{Value: ua.Browser.Name > 0}, nil

	// Following values are always false in interpreter
	// because they seem to be able to set in Fastly edge architecture
	// Or not be publicly its spec
	case "client.class.checker",
		"client.class.downloader",
		"client.class.feedreader",
		"client.class.filter",
		"client.class.masquerading",
		"client.class.spam",
		"client.platform.mediaplayer",
		"req.backend.is_shield",
		"req.is_background_fetch",
		"req.is_clustering",
		"req.is_esi_subreq",
		"resp.stale",
		"resp.stale.is_error",
		"resp.stale.is_revalidating",
		"workspace.overflowed":
		return &value.Boolean{Value: false}, nil

	case "client.display.touchscreen":
		isTouch := ua.DeviceType == uasurfer.DevicePhone ||
			ua.DeviceType == uasurfer.DeviceTablet ||
			ua.DeviceType == uasurfer.DeviceWearable
		return &value.Boolean{Value: isTouch}, nil
	case "client.platform.ereader":
		return &value.Boolean{Value: ua.OS.Name == uasurfer.OSKindle}, nil
	case "client.platform.gameconsole":
		isGame := ua.OS.Name == uasurfer.OSPlaystation ||
			ua.OS.Name == uasurfer.OSXbox ||
			ua.OS.Name == uasurfer.OSNintendo
		return &value.Boolean{Value: isGame}, nil
	case "client.platform.mobile":
		return &value.Boolean{Value: ua.DeviceType == uasurfer.DevicePhone}, nil
	case "client.platform.smarttv":
		return &value.Boolean{Value: ua.DeviceType == uasurfer.DeviceTV}, nil
	case "client.platform.tablet":
		return &value.Boolean{Value: ua.DeviceType == uasurfer.DeviceTablet}, nil
	case "client.platform.tvplayer":
		return &value.Boolean{Value: ua.DeviceType == uasurfer.DeviceTV}, nil
	case "fastly_info.edge.is_tls":
		return &value.Boolean{Value: req.TLS != nil}, nil
	case "fastly_info.is_h2":
		return &value.Boolean{Value: req.ProtoMajor == 2}, nil
	case "fastly_info.is_h3":
		return &value.Boolean{Value: req.ProtoMajor == 3}, nil

	// Backend is always healthy on simulator
	case "req.backend.healthy":
		return &value.Boolean{Value: true}, nil

	case "req.is_ssl":
		return &value.Boolean{Value: req.TLS != nil}, nil
	case "req.protocol":
		protocol := "http"
		if req.TLS != nil {
			protocol = "https"
		}
		return &value.String{Value: protocol}, nil
	case "client.geo.latitude":
		return &value.Float{Value: 35.688681}, nil
	case "client.geo.longitude":
		return &value.Float{Value: 139.762253}, nil
	case "fastly.error":
		return &value.String{Value: ""}, nil
	case "math.1_PI":
		return &value.Float{Value: 1 / math.Pi}, nil
	case "math.2_PI":
		return &value.Float{Value: 2 / math.Pi}, nil
	case "math.2_SQRTPI":
		return &value.Float{Value: 2 / math.SqrtPi}, nil
	case "math.2PI":
		return &value.Float{Value: 2 * math.Pi}, nil
	case "math.E":
		return &value.Float{Value: math.E}, nil
	case "math.FLOAT_EPSILON":
		return &value.Float{Value: math.Pow(2, -52)}, nil
	case "math.FLOAT_MAX":
		return &value.Float{Value: math.MaxFloat64}, nil
	case "math.FLOAT_MIN":
		return &value.Float{Value: math.SmallestNonzeroFloat64}, nil
	case "math.LN10":
		return &value.Float{Value: math.Ln10}, nil
	case "math.LN2":
		return &value.Float{Value: math.Ln2}, nil
	case "math.LOG10E":
		return &value.Float{Value: math.Log10E}, nil
	case "math.LOG2E":
		return &value.Float{Value: math.Log2E}, nil
	case "math.NAN":
		return &value.Float{IsNAN: true}, nil
	case "math.NEG_HUGE_VAL":
		return &value.Float{IsNegativeInf: true}, nil
	case "math.NEG_INFINITY":
		return &value.Float{IsNegativeInf: true}, nil
	case "math.PHI":
		return &value.Float{Value: math.Phi}, nil
	case "math.PI":
		return &value.Float{Value: math.Pi}, nil
	case "math.PI_2":
		return &value.Float{Value: math.Pi / 2}, nil
	case "math.PI_4":
		return &value.Float{Value: math.Pi / 4}, nil
	case "math.POS_HUGE_VAL":
		return &value.Float{IsPositiveInf: true}, nil
	case "math.POS_INFINITY":
		return &value.Float{IsPositiveInf: true}, nil
	case "math.SQRT1_2":
		return &value.Float{Value: 1 / math.Sqrt2}, nil
	case "math.SQRT2":
		return &value.Float{Value: math.Sqrt2}, nil
	case "math.TAU":
		return &value.Float{Value: math.Pi * 2}, nil

	// AS Number always indicates "Reserved" defined by RFC7300
	// see: https://datatracker.ietf.org/doc/html/rfc7300
	case "client.as.number":
		return &value.Integer{Value: 4294967294}, nil
	case "client.as.name":
		return &value.String{Value: "Reserved"}, nil

	// Client display infos are unknown. Always returns -1
	case "client.display.height",
		"client.display.ppi",
		"client.display.width":
		return &value.Integer{Value: -1}, nil

	// Client geo values always return 0
	case "client.geo.area_code",
		"client.geo.metro_code",
		"client.geo.utc_offset":
		return &value.Integer{Value: 0}, nil

	// Alias of client.geo.utc_offset
	case "client.geo.gmt_offset":
		return v.Get(s, "client.geo.utc_offset")

	// Client could not fully identified so returns false
	case "client.identified":
		return &value.Boolean{Value: false}, nil

	case "client.port":
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
	case "client.requests":
		return &value.Integer{Value: 1}, nil

	// Returns common value -- do not consider of clustering
	// see: https://developer.fastly.com/reference/vcl/variables/miscellaneous/fastly-ff-visits-this-service/
	case "fastly.ff.visits_this_service":
		switch s {
		case context.MissScope, context.HitScope, context.FetchScope:
			return &value.Integer{Value: 1}, nil
		default:
			return &value.Integer{Value: 0}, nil
		}

	// Returns fixed value which is presented on Fastly fiddle
	case "math.FLOAT_DIG":
		return &value.Integer{Value: 15}, nil
	case "math.FLOAT_MANT_DIG":
		return &value.Integer{Value: 53}, nil
	case "math.FLOAT_MAX_10_EXP":
		return &value.Integer{Value: 308}, nil
	case "math.FLOAT_MAX_EXP":
		return &value.Integer{Value: 1024}, nil
	case "math.FLOAT_MIN_10_EXP":
		return &value.Integer{Value: -307}, nil
	case "math.FLOAT_MIN_EXP":
		return &value.Integer{Value: -1021}, nil
	case "math.FLOAT_RADIX":
		return &value.Integer{Value: 2}, nil
	case "math.INTEGER_BIT":
		return &value.Integer{Value: 64}, nil
	case "math.INTEGER_MAX":
		return &value.Integer{Value: 9223372036854775807}, nil
	case "math.INTEGER_MIN":
		return &value.Integer{Value: -9223372036854775808}, nil

	case "req.header_bytes_read":
		var headerBytes int64
		// FIXME: Do we need to include total byte header LF bytes?
		for k, v := range req.Header {
			// add ":" character that header separator character
			headerBytes += int64(len(k) + 1 + len(strings.Join(v, ";")))
		}
		return &value.Integer{Value: headerBytes}, nil
	case "req.restarts":
		return &value.Integer{Value: int64(v.ctx.Restarts)}, nil

	// Returns always 1 because VCL is generated locally
	case "req.vcl.generation":
		return &value.Integer{Value: 1}, nil
	case "req.vcl.version":
		return &value.Integer{Value: 1}, nil

	case "server.port":
		return &value.Integer{Value: int64(3124)}, nil // fixed server port number

	// workspace related values respects Fastly fiddle one
	case "workspace.bytes_free":
		return &value.Integer{Value: 125008}, nil
	case "workspace.bytes_total":
		return &value.Integer{Value: 139392}, nil

	// backend.src_ip always incicates this server, means localhost
	case "beresp.backend.src_ip":
		return &value.IP{Value: net.IPv4(127, 0, 0, 1)}, nil
	case "server.ip":
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

	case "req.backend":
		return v.ctx.Backend, nil
	case "req.grace":
		return v.Get(s, "req.max_stale_if_error")

	// Return current state
	case "req.max_stale_if_error":
		return v.ctx.MaxStaleIfError, nil
	case "req.max_stale_while_revalidate":
		return v.ctx.MaxStaleWhileRevalidate, nil

	case "time.elapsed":
		start, ok := req.Context().Value(context.RequestStartKey).(time.Time)
		if !ok {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not get request start time",
			))
		}
		return &value.RTime{Value: time.Since(start)}, nil
	case "client.bot.name":
		if !ua.IsBot() {
			return &value.String{Value: ""}, nil
		}
		return &value.String{Value: ua.Browser.Name.String()}, nil
	case "client.browser.name":
		return &value.String{Value: ua.Browser.Name.String()}, nil
	case "client.browser.version":
		v := ua.Browser.Version
		return &value.String{
			Value: fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch),
		}, nil

	// TODO: respect artbitrary request
	case "client.geo.city":
	case "client.geo.city.ascii":
	case "client.geo.city.latin1":
	case "client.geo.city.utf8":
	case "client.geo.conn_speed":
	case "client.geo.conn_type":
	case "client.geo.continent_code":
	case "client.geo.country_code":
	case "client.geo.country_code3":
	case "client.geo.country_name":
	case "client.geo.country_name.ascii":
	case "client.geo.country_name.latin1":
	case "client.geo.country_name.utf8":
	case "client.geo.ip_override":
	case "client.geo.postal_code":
	case "client.geo.proxy_description":
	case "client.geo.proxy_type":
	case "client.geo.region":
	case "client.geo.region.ascii":
	case "client.geo.region.latin1":
	case "client.geo.region.utf8":

	case "client.identity":
		if v.ctx.ClientIdentity == nil {
			// default as client.ip
			idx := strings.LastIndex(req.RemoteAddr, ":")
			if idx == -1 {
				return &value.String{Value: req.RemoteAddr}, nil
			}
			return &value.String{Value: req.RemoteAddr[:idx]}, nil
		}
		return v.ctx.ClientIdentity, nil

	case "client.ip":
		idx := strings.LastIndex(req.RemoteAddr, ":")
		if idx == -1 {
			return &value.IP{Value: net.ParseIP(req.RemoteAddr)}, nil
		}
		return &value.IP{Value: net.ParseIP(req.RemoteAddr[:idx])}, nil

	case "client.os.name":
		return &value.String{Value: ua.OS.Name.String()}, nil
	case "client.os.version":
		v := ua.OS.Version
		return &value.String{
			Value: fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch),
		}, nil

	// Always empty string
	case "client.platform.hwtype":
		return &value.String{Value: ""}, nil

	case "fastly_info.state":
		return &value.String{Value: v.ctx.State}, nil
	case "LF":
		return &value.String{Value: "\n"}, nil
	case "now.sec":
		return &value.String{Value: fmt.Sprint(time.Now().Unix())}, nil
	case "req.body":
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
	case "req.body.base64":
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
	case "req.digest":
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
	case "req.method":
		return &value.String{Value: req.Method}, nil
	case "req.postbody":
		return v.Get(s, "req.body")
	case "req.proto":
		return &value.String{Value: req.Proto}, nil
	case "req.request":
		return v.Get(s, "req.method")
	case "req.service_id":
		id := os.Getenv("FASYLY_SERVICE_ID")
		if id == "" {
			id = "falco-virtual-service-id"
		}
		return &value.String{Value: id}, nil
	case "req.topurl": // FIXME: what is the difference of req.url ?
		u := req.URL.Path
		if v := req.URL.RawQuery; v != "" {
			u += "?" + v
		}
		if v := req.URL.RawFragment; v != "" {
			u += "#" + v
		}
		return &value.String{Value: u}, nil
	case "req.url":
		u := req.URL.Path
		if v := req.URL.RawQuery; v != "" {
			u += "?" + v
		}
		if v := req.URL.RawFragment; v != "" {
			u += "#" + v
		}
		return &value.String{Value: u}, nil
	case "req.url.basename":
		return &value.String{
			Value: filepath.Base(req.URL.Path),
		}, nil
	case "req.url.dirname":
		return &value.String{
			Value: filepath.Dir(req.URL.Path),
		}, nil
	case "req.url.ext":
		ext := filepath.Ext(req.URL.Path)
		return &value.String{
			Value: strings.TrimPrefix(ext, "."),
		}, nil
	case "req.url.path":
		return &value.String{Value: req.URL.Path}, nil
	case "req.url.qs":
		return &value.String{Value: req.URL.RawQuery}, nil
	case "req.vcl":
		id := os.Getenv("FASYLY_SERVICE_ID")
		if id == "" {
			id = "falco-virtual-service-id"
		}
		return &value.String{
			Value: fmt.Sprintf("%s.%d_%d-%s", id, 1, 0, strings.Repeat("0", 32)),
		}, nil
	case "req.vcl.md5":
		id := os.Getenv("FASYLY_SERVICE_ID")
		if id == "" {
			id = "falco-virtual-service-id"
		}
		vcl := fmt.Sprintf("%s.%d_%d-%s", id, 1, 0, strings.Repeat("0", 32))
		return &value.String{
			Value: fmt.Sprintf("%x", md5.Sum([]byte(vcl))),
		}, nil
	case "req.xid":
		return &value.String{Value: xid.New().String()}, nil

	// Fixed values
	case "server.datacenter":
		return &value.String{Value: "NRT"}, nil
	case "server.hostname":
		return &value.String{Value: "cache-nrt-knrt7000001"}, nil
	case "server.identity":
		return &value.String{Value: "cache-nrt-knrt7000001"}, nil
	case "server.region":
		return &value.String{Value: "Asia"}, nil
	case "stale.exists":
		return v.ctx.StaleContents, nil
	case "time.elapsed.msec":
		start, ok := req.Context().Value(context.RequestStartKey).(time.Time)
		if !ok {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not get request start time",
			))
		}
		return &value.String{
			Value: fmt.Sprint(time.Since(start).Milliseconds()),
		}, nil
	case "time.elapsed.msec_frac":
		start, ok := req.Context().Value(context.RequestStartKey).(time.Time)
		if !ok {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not get request start time",
			))
		}
		return &value.String{
			Value: fmt.Sprintf("%03d", time.Since(start).Milliseconds()),
		}, nil
	case "time.elapsed.sec":
		start, ok := req.Context().Value(context.RequestStartKey).(time.Time)
		if !ok {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not get request start time",
			))
		}
		return &value.String{
			Value: fmt.Sprint(int64(time.Since(start).Seconds())),
		}, nil
	case "time.elapsed.usec":
		start, ok := req.Context().Value(context.RequestStartKey).(time.Time)
		if !ok {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not get request start time",
			))
		}
		return &value.String{
			Value: fmt.Sprint(time.Since(start).Microseconds()),
		}, nil
	case "time.elapsed.usec_frac":
		start, ok := req.Context().Value(context.RequestStartKey).(time.Time)
		if !ok {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not get request start time",
			))
		}
		return &value.String{
			Value: fmt.Sprintf("%06d", time.Since(start).Microseconds()),
		}, nil
	case "time.start.msec":
		start, ok := req.Context().Value(context.RequestStartKey).(time.Time)
		if !ok {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not get request start time",
			))
		}
		return &value.String{
			Value: fmt.Sprint(start.UnixMilli()),
		}, nil
	case "time.start.msec_frac":
		start, ok := req.Context().Value(context.RequestStartKey).(time.Time)
		if !ok {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not get request start time",
			))
		}
		return &value.String{
			Value: fmt.Sprint(start.UnixMilli() % 1000),
		}, nil
	case "time.start.sec":
		start, ok := req.Context().Value(context.RequestStartKey).(time.Time)
		if !ok {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not get request start time",
			))
		}
		return &value.String{
			Value: fmt.Sprint(start.Unix()),
		}, nil
	case "time.start.usec":
		start, ok := req.Context().Value(context.RequestStartKey).(time.Time)
		if !ok {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not get request start time",
			))
		}
		return &value.String{
			Value: fmt.Sprint(start.UnixMicro()),
		}, nil
	case "time.start.usec_frac":
		start, ok := req.Context().Value(context.RequestStartKey).(time.Time)
		if !ok {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not get request start time",
			))
		}
		return &value.String{
			Value: fmt.Sprint(start.UnixMicro() % 1000000),
		}, nil
	case "now":
		return &value.Time{Value: time.Now()}, nil
	case "time.start":
		start, ok := req.Context().Value(context.RequestStartKey).(time.Time)
		if !ok {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not get request start time",
			))
		}
		return &value.Time{Value: start}, nil
	}

	if val := v.getFromRegex(name); val != nil {
		return val, nil
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
		// If name is Cookie, header name can contain ":" with cookie name
		if !strings.Contains(name, ":") {
			return &value.String{
				Value: v.ctx.Request.Header.Get(match[1]),
			}
		}
		spl := strings.SplitN(name, ":", 2)
		if !strings.EqualFold(spl[0], "cookie") {
			return &value.String{
				Value: v.ctx.Request.Header.Get(match[1]),
			}
		}

		for _, c := range v.ctx.Request.Cookies() {
			if c.Name == spl[1] {
				return &value.String{Value: c.Value}
			}
		}
		return &value.String{Value: ""}
	}

	// Ratecounter variable matching
	if match := rateCounterRegex.FindStringSubmatch(name); match != nil {
		var val float64
		// all ratecounter variable value returns 1.0 fixed value
		switch match[1] {
		case "rate.10s",
			"rate.1s",
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
	case "client.identity":
		if v.ctx.ClientIdentity == nil {
			v.ctx.ClientIdentity = &value.String{Value: ""}
		}
		if err := doAssign(v.ctx.ClientIdentity, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "resp.stale":
		if err := doAssign(v.ctx.Stale, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "resp.stale.is_error":
		if err := doAssign(v.ctx.StaleIsError, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "resp.stale.is_revalidating":
		if err := doAssign(v.ctx.StaleIsRevalidating, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "req.backend":
		if err := doAssign(v.ctx.Backend, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "req.grace":
		return v.Set(s, "req.max_stale_if_error", operator, val)
	case "req.max_stale_if_error":
		if err := doAssign(v.ctx.MaxStaleIfError, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "req.max_stale_while_revalidate":
		if err := doAssign(v.ctx.MaxStaleWhileRevalidate, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "client.geo.ip_override":
		if err := doAssign(v.ctx.ClientGeoIpOverride, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "req.method":
		left := &value.String{Value: v.ctx.Request.Method}
		if err := doAssign(left, operator, val); err != nil {
			return errors.WithStack(err)
		}
		v.ctx.Request.Method = left.Value
		return nil
	case "req.request":
		return v.Set(s, "req.method", operator, val)
	case "req.url":
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
		v.ctx.Request.URL.Path = parsed.Path
		v.ctx.Request.URL.RawQuery = parsed.RawQuery
		v.ctx.Request.URL.RawFragment = parsed.RawFragment
		return nil
	}

	if match := requestHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		v.ctx.Request.Header.Set(match[1], val.String())
		return nil
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
	v.ctx.Request.Header.Del(match[1])
	return nil
}

var _ Variable = &AllScopeVariables{}
