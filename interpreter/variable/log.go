package variable

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"
	"strconv"

	"io/ioutil"
	"net/http"
	"net/netip"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

type LogScopeVariables struct {
	Variable
	base *AllScopeVariables
	ctx  *context.Context
}

func NewLogScopeVariables(ctx *context.Context) *LogScopeVariables {
	return &LogScopeVariables{
		base: NewAllScopeVariables(ctx),
		ctx:  ctx,
	}
}

func (v *LogScopeVariables) Get(s context.Scope, name string) (value.Value, error) {
	bereq := v.ctx.BackendRequest
	req := v.ctx.Request

	switch name {
	case "bereq.body_bytes_written":
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(bereq.Body); err != nil {
			return value.Null, errors.WithStack(err)
		}
		body := buf.Bytes()
		bereq.Body = ioutil.NopCloser(bytes.NewReader(buf.Bytes()))
		return &value.Integer{Value: int64(len(body))}, nil

	case "bereq.bytes_written":
		// TODO: we need to implement backend communication without net/http package
		// because we have to know more raw socket informations
		return &value.Integer{Value: 0}, nil

	case "bereq.header_bytes_written":
		var headerBytes int64
		// FIXME: Do we need to include total byte header LF bytes?
		for k, v := range bereq.Header {
			// add ":" character that header separator character
			headerBytes += int64(len(k) + 1 + len(strings.Join(v, ";")))
		}
		return &value.Integer{Value: headerBytes}, nil

	case "client.socket.congestion_algorithm":
		return v.ctx.ClientSocketCongestionAlgorithm, nil
	case "client.socket.cwnd":
		// Sometimes change this value but we don't know how change it without set statement
		return &value.Integer{Value: 60}, nil
	case "client.socket.nexthop":
		return &value.IP{Value: net.IPv4(127, 0, 0, 1)}, nil
	case "client.socket.pace":
		return &value.Integer{Value: 0}, nil
	case "client.socket.ploss":
		return &value.Float{Value: 0}, nil

	case "esi.allow_inside_cdata":
		return v.ctx.EsiAllowInsideCData, nil

	case "fastly_info.is_cluster_edge":
		return &value.Boolean{Value: false}, nil

	case "obj.age":
		// fixed value
		return &value.RTime{Value: 60 * time.Second}, nil
	case "obj.entered":
		return &value.RTime{Value: 60 * time.Second}, nil
	case "obj.grace":
		return v.ctx.ObjectGrace, nil
	case "obj.hits":
		return &value.Integer{Value: 1}, nil
	case "obj.is_pci":
		return &value.Boolean{Value: false}, nil
	case "obj.lastuse":
		return &value.RTime{Value: 60 * time.Second}, nil
	case "obj.stale_if_error":
		// alias for obj.grace
		return v.ctx.ObjectGrace, nil
	case "obj.stale_while_revalidate":
		return &value.RTime{Value: 60 * time.Second}, nil
	case "obj.ttl":
		return v.ctx.ObjectTTL, nil

	case "req.is_ipv6":
		addr, ok := v.ctx.Request.Context().Value(context.ClientAddrKey).(*net.TCPAddr)
		if !ok {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not get client connection info",
			))
		}
		parsed, err := netip.ParseAddr(addr.IP.String())
		if err != nil {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not parse remote address",
			))
		}
		return &value.Boolean{Value: parsed.Is6()}, nil
	case "req.is_purge":
		return &value.Boolean{Value: v.ctx.Request.Method == "PURGE"}, nil

	case "req.backend.ip":
		return &value.IP{Value: net.IPv4(127, 0, 0, 1)}, nil
	case "req.backend.is_cluster":
		return &value.Boolean{Value: false}, nil
	case "req.backend.name":
		var name string
		if v.ctx.Backend != nil {
			name = v.ctx.Backend.Value.Name.Value
		}
		return &value.String{Value: name}, nil
	case "req.backend.port":
		if v.ctx.Backend == nil {
			return &value.Integer{Value: 0}, nil
		}
		var port int64
		for _, p := range v.ctx.Backend.Value.Properties {
			if p.Key.Value != "port" {
				continue
			}
			n, err := strconv.ParseInt(p.Value.String(), 10, 64)
			if err != nil {
				return value.Null, errors.WithStack(err)
			}
			port = n
			break
		}
		return &value.Integer{Value: port}, nil
	case "req.body_bytes_read":
		var buf bytes.Buffer
		n, err := buf.ReadFrom(req.Body)
		if err != nil {
			return value.Null, errors.WithStack(err)
		}
		req.Body = ioutil.NopCloser(bytes.NewReader(buf.Bytes()))
		return &value.Integer{Value: n}, nil
	case "req.bytes_read":
		var readBytes int64
		// FIXME: Do we need to include total byte header LF bytes?
		for k, v := range req.Header {
			// add ":" character that header separator character
			readBytes += int64(len(k) + 1 + len(strings.Join(v, ";")))
		}
		var buf bytes.Buffer
		n, err := buf.ReadFrom(req.Body)
		if err != nil {
			return value.Null, errors.WithStack(err)
		}
		req.Body = ioutil.NopCloser(bytes.NewReader(buf.Bytes()))
		readBytes += n
		return &value.Integer{Value: readBytes}, nil
	// Digest ratio will return fixed value
	case "req.digest.ratio":
		return &value.Float{Value: 0.4}, nil

	// FIXME: We need to send actual request to the backend
	case "resp.body_bytes_written":
		return &value.Integer{Value: 0}, nil
	case "resp.bytes_written":
		return &value.Integer{Value: 0}, nil
	case "resp.completed":
		return &value.Boolean{Value: true}, nil
	case "resp.header_bytes_written":
		return &value.Integer{Value: 0}, nil
	case "resp.is_locally_generated":
		return &value.Boolean{Value: false}, nil
	case "resp.proto":
		return &value.String{Value: "HTTP/1.1"}, nil
	case "resp.response":
		return &value.String{Value: "Fake Response"}, nil
	case "resp.status":
		return &value.Integer{Value: 200}, nil

	case "time.end":
		return &value.Time{Value: v.ctx.RequestEndTime}, nil
	case "time.end.msec":
		return &value.String{
			Value: fmt.Sprint(v.ctx.RequestEndTime.UnixMilli()),
		}, nil
	case "time.end.msec_frac":
		return &value.String{
			Value: fmt.Sprintf("%03d", v.ctx.RequestEndTime.UnixMilli()),
		}, nil
	case "time.end.sec":
		return &value.String{
			Value: fmt.Sprint(v.ctx.RequestEndTime.Unix()),
		}, nil
	case "time.end.usec":
		return &value.String{
			Value: fmt.Sprint(v.ctx.RequestEndTime.UnixMicro()),
		}, nil
	case "time.end.usec_frac":
		return &value.String{
			Value: fmt.Sprint(v.ctx.RequestEndTime.UnixMicro()),
		}, nil
	case "time.to_first_byte":
		// TODO: this logic is only calculate response - request time.
		// It means that is not correct RTIME value because TFB is the first byte from response.
		return &value.RTime{
			Value: time.Now().Sub(v.ctx.RequestEndTime),
		}, nil

	// FIXME: segmented_caching related variables is just fake value
	case "segmented_caching.autopurged":
		return &value.Boolean{Value: false}, nil
	case "segmented_caching.block_number":
		return &value.Integer{Value: 1}, nil
	case "segmented_caching.block_size":
		return &value.Integer{Value: 1}, nil
	case "segmented_caching.cancelled":
		return &value.Boolean{Value: false}, nil
	case "segmented_caching.client_req.is_open_ended":
		return &value.Boolean{Value: false}, nil
	case "segmented_caching.client_req.is_range":
		return &value.Boolean{Value: req.Header.Get("Range") != ""}, nil
	case "segmented_caching.client_req.range_high":
		spl := strings.SplitN(req.Header.Get("Range"), "-", 2)
		if len(spl) != 2 {
			return &value.Integer{Value: 0}, nil
		}
		high, err := strconv.ParseInt(spl[1], 10, 64)
		if err != nil {
			return value.Null, errors.WithStack(err)
		}
		return &value.Integer{Value: high}, nil
	case "segmented_caching.client_req.range_low":
		spl := strings.SplitN(req.Header.Get("Range"), "-", 2)
		if len(spl) != 2 {
			return &value.Integer{Value: 0}, nil
		}
		low, err := strconv.ParseInt(spl[0], 10, 64)
		if err != nil {
			return value.Null, errors.WithStack(err)
		}
		return &value.Integer{Value: low}, nil
	case "segmented_caching.completed":
		return &value.Boolean{Value: false}, nil
	case "segmented_caching.error":
		return &value.String{Value: ""}, nil
	case "segmented_caching.failed":
		return &value.Boolean{Value: false}, nil
	case "segmented_caching.is_inner_req":
		return &value.Boolean{Value: false}, nil
	case "segmented_caching.is_outer_req":
		return &value.Boolean{Value: true}, nil
	case "segmented_caching.obj.complete_length":
		return &value.Integer{Value: 0}, nil
	case "segmented_caching.rounded_req.range_high":
		return &value.Integer{Value: 0}, nil
	case "segmented_caching.rounded_req.range_low":
		return &value.Integer{Value: 0}, nil
	case "segmented_caching.total_blocks":
		return &value.Integer{Value: 0}, nil
	}

	// Look up shared variables
	if val, err := GetTCPInfoVariable(name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
	}
	if val, err := GetQuicVariable(name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
	}
	if val, err := GetTLSVariable(v.ctx.Request.TLS, name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
	}
	if val, err := GetFastlyInfoVairable(name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
	}
	if val, err := GetWafVariables(v.ctx, name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
	}

	if val := v.getFromRegex(name); val != nil {
		return val, nil
	}

	// If not found, also look up all scope value
	val, err := v.base.Get(s, name)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}
	return val, nil
}

func (v *LogScopeVariables) getFromRegex(name string) value.Value {
	// HTTP response header matching
	if match := responseHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		return &value.String{
			Value: v.ctx.Request.Header.Get(match[1]),
		}
	}
	return nil
}

func (v *LogScopeVariables) Set(s context.Scope, name, operator string, val value.Value) error {
	switch name {
	case "client.socket.congestion_algorithm":
		if err := doAssign(v.ctx.ClientSocketCongestionAlgorithm, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "client.socket.cwnd":
		if err := doAssign(v.ctx.ClientSocketCwnd, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "client.socket.pace":
		if err := doAssign(v.ctx.ClientSocketPace, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "obj.grace":
		if err := doAssign(v.ctx.ObjectGrace, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "obj.ttl":
		if err := doAssign(v.ctx.ObjectTTL, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "resp.response":
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(v.ctx.Response.Body); err != nil {
			return errors.WithStack(err)
		}
		left := &value.String{Value: buf.String()}
		if err := doAssign(left, operator, val); err != nil {
			return errors.WithStack(err)
		}
		v.ctx.Response.Body = ioutil.NopCloser(strings.NewReader(left.Value))
		return nil
	case "resp.status":
		left := &value.Integer{Value: int64(v.ctx.Response.StatusCode)}
		if err := doAssign(left, operator, val); err != nil {
			return errors.WithStack(err)
		}
		v.ctx.Response.StatusCode = int(left.Value)
		v.ctx.Response.Status = http.StatusText(int(left.Value))
		return nil
	case "segmented_caching.block_size":
		if err := doAssign(v.ctx.SegmentedCacheingBlockSize, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	}

	if ok, err := SetWafVariables(v.ctx, name, operator, val); err != nil {
		return errors.WithStack(err)
	} else if ok {
		return nil
	}

	if match := responseHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		v.ctx.Response.Header.Set(name, val.String())
		return nil
	}

	// If not found, pass to all scope value
	return v.base.Set(s, name, operator, val)
}

func (v *LogScopeVariables) Add(s context.Scope, name string, val value.Value) error {
	// Add statement could be use only for HTTP header
	match := responseHttpHeaderRegex.FindStringSubmatch(name)
	if match != nil {
		// Nothing values to be enable to add in PASS, pass to base
		return v.base.Add(s, name, val)
	}

	v.ctx.Response.Header.Add(match[1], val.String())
	return nil
}

func (v *LogScopeVariables) Unset(s context.Scope, name string) error {
	match := responseHttpHeaderRegex.FindStringSubmatch(name)
	if match == nil {
		// Nothing values to be enable to unset in PASS, pass to base
		return v.base.Unset(s, name)
	}
	v.ctx.Response.Header.Del(match[1])
	return nil
}
