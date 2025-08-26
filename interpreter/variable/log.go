package variable

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"net/http"
	"net/netip"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/limitations"
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

// nolint: funlen,gocognit,gocyclo
func (v *LogScopeVariables) Get(s context.Scope, name string) (value.Value, error) {
	bereq := v.ctx.BackendRequest
	req := v.ctx.Request

	switch name {
	case BEREQ_BODY_BYTES_WRITTEN:
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(bereq.Body); err != nil {
			return value.Null, errors.WithStack(err)
		}
		body := buf.Bytes()
		bereq.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
		return &value.Integer{Value: int64(len(body))}, nil

	case BEREQ_BYTES_WRITTEN:
		// TODO: we need to implement backend communication without net/http package
		// because we have to know more raw socket informations
		return &value.Integer{Value: 0}, nil

	case BEREQ_HEADER_BYTES_WRITTEN:
		var headerBytes int64
		// FIXME: Do we need to include total byte header LF bytes?
		for k, v := range bereq.Header {
			// add ":" character that header separator character
			headerBytes += int64(len(k) + 1 + len(strings.Join(v, ";")))
		}
		return &value.Integer{Value: headerBytes}, nil

	case CLIENT_SOCKET_CONGESTION_ALGORITHM:
		return v.ctx.ClientSocketCongestionAlgorithm, nil
	case CLIENT_SOCKET_CWND:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		// Sometimes change this value but we don't know how change it without set statement
		return &value.Integer{Value: 60}, nil
	case CLIENT_SOCKET_NEXTHOP:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.IP{Value: net.IPv4(127, 0, 0, 1)}, nil
	case CLIENT_SOCKET_PACE:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Integer{Value: 0}, nil
	case CLIENT_SOCKET_PLOSS:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Float{Value: 0}, nil

	case ESI_ALLOW_INSIDE_CDATA:
		return v.ctx.EsiAllowInsideCData, nil

	case FASTLY_INFO_IS_CLUSTER_EDGE:
		return &value.Boolean{Value: false}, nil

	case OBJ_AGE:
		if v.ctx.CacheHitItem != nil {
			return &value.RTime{Value: time.Since(v.ctx.CacheHitItem.EntryTime)}, nil
		}
		return &value.RTime{Value: 0}, nil // 0s
	case OBJ_CACHEABLE:
		return v.ctx.BackendResponseCacheable, nil
	case OBJ_ENTERED:
		if v.ctx.CacheHitItem != nil {
			return &value.RTime{Value: time.Since(v.ctx.CacheHitItem.EntryTime)}, nil
		}
		return &value.RTime{Value: 0}, nil
	case OBJ_GRACE:
		return v.ctx.ObjectGrace, nil
	case OBJ_HITS:
		if v.ctx.CacheHitItem != nil {
			return &value.Integer{Value: int64(v.ctx.CacheHitItem.Hits)}, nil
		}
		return &value.Integer{Value: 0}, nil
	case OBJ_IS_PCI:
		return &value.Boolean{Value: false}, nil // fixed value
	case OBJ_LASTUSE:
		if v.ctx.CacheHitItem != nil {
			return &value.RTime{Value: v.ctx.CacheHitItem.LastUsed}, nil
		}
		return &value.RTime{Value: 0}, nil
	case OBJ_STALE_IF_ERROR:
		// alias for obj.grace
		return v.ctx.ObjectGrace, nil
	case OBJ_STALE_WHILE_REVALIDATE:
		// Return fixed value because we don't support SWR yet
		return &value.RTime{Value: 60 * time.Second}, nil
	case OBJ_TTL:
		return v.ctx.ObjectTTL, nil

	case REQ_IS_IPV6:
		parsed, err := netip.ParseAddr(v.ctx.Request.RemoteAddr)
		if err != nil {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not parse remote address",
			))
		}
		return &value.Boolean{Value: parsed.Is6()}, nil
	case REQ_IS_PURGE:
		return &value.Boolean{Value: v.ctx.Request.Method == "PURGE"}, nil

	case REQ_BACKEND_IP:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.IP{Value: net.IPv4(127, 0, 0, 1)}, nil
	case REQ_BACKEND_IS_CLUSTER:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Boolean{Value: false}, nil
	case REQ_BACKEND_NAME:
		var name string
		if v.ctx.Backend != nil {
			name = v.ctx.Backend.Value.Name.Value
		}
		return &value.String{Value: name}, nil
	case REQ_BACKEND_PORT:
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
	case REQ_BODY_BYTES_READ:
		var buf bytes.Buffer
		n, err := buf.ReadFrom(req.Body)
		if err != nil {
			return value.Null, errors.WithStack(err)
		}
		req.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
		return &value.Integer{Value: n}, nil
	case REQ_BYTES_READ:
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
		req.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
		readBytes += n
		return &value.Integer{Value: readBytes}, nil
	// Digest ratio will return fixed value if not override
	case REQ_DIGEST_RATIO:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Float{Value: 0.4}, nil

	// FIXME: We need to send actual request to the backend
	case RESP_BODY_BYTES_WRITTEN:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Integer{Value: 0}, nil
	case RESP_BYTES_WRITTEN:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Integer{Value: 0}, nil
	case RESP_COMPLETED:
		return &value.Boolean{Value: true}, nil
	case RESP_HEADER_BYTES_WRITTEN:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Integer{Value: 0}, nil
	case RESP_IS_LOCALLY_GENERATED:
		return v.ctx.IsLocallyGenerated, nil
	case RESP_PROTO:
		return &value.String{Value: v.ctx.Response.Proto}, nil
	case RESP_RESPONSE:
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(v.ctx.Response.Body); err != nil {
			return value.Null, errors.WithStack(err)
		}
		v.ctx.Response.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
		return &value.String{Value: buf.String()}, nil
	case RESP_STATUS:
		return &value.Integer{Value: int64(v.ctx.Response.StatusCode)}, nil

	case TIME_END:
		return &value.Time{Value: v.ctx.RequestEndTime}, nil
	case TIME_END_MSEC:
		return &value.String{
			Value: fmt.Sprint(v.ctx.RequestEndTime.UnixMilli()),
		}, nil
	case TIME_END_MSEC_FRAC:
		return &value.String{
			Value: fmt.Sprintf("%03d", v.ctx.RequestEndTime.UnixMilli()),
		}, nil
	case TIME_END_SEC:
		return &value.String{
			Value: fmt.Sprint(v.ctx.RequestEndTime.Unix()),
		}, nil
	case TIME_END_USEC:
		return &value.String{
			Value: fmt.Sprint(v.ctx.RequestEndTime.UnixMicro()),
		}, nil
	case TIME_END_USEC_FRAC:
		return &value.String{
			Value: fmt.Sprint(v.ctx.RequestEndTime.UnixMicro()),
		}, nil
	case TIME_TO_FIRST_BYTE:
		// TODO: this logic is only calculate response - request time.
		// It means that is not correct RTIME value because TFB is the first byte from response.
		return &value.RTime{
			Value: time.Since(v.ctx.RequestEndTime),
		}, nil

	// FIXME: segmented_caching related variables is just fake value
	case SEGMENTED_CACHING_AUTOPURGED:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Boolean{Value: false}, nil
	case SEGMENTED_CACHING_BLOCK_NUMBER:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Integer{Value: 1}, nil
	case SEGMENTED_CACHING_BLOCK_SIZE:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Integer{Value: 1}, nil
	case SEGMENTED_CACHING_CANCELLED: // nolint: misspell
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Boolean{Value: false}, nil
	case SEGMENTED_CACHING_CLIENT_REQ_IS_OPEN_ENDED:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Boolean{Value: false}, nil
	case SEGMENTED_CACHING_CLIENT_REQ_IS_RANGE:
		return &value.Boolean{Value: req.Header.Get("Range") != ""}, nil
	case SEGMENTED_CACHING_CLIENT_REQ_RANGE_HIGH:
		spl := strings.SplitN(req.Header.Get("Range"), "-", 2)
		if len(spl) != 2 {
			return &value.Integer{Value: 0}, nil
		}
		high, err := strconv.ParseInt(spl[1], 10, 64)
		if err != nil {
			return value.Null, errors.WithStack(err)
		}
		return &value.Integer{Value: high}, nil
	case SEGMENTED_CACHING_CLIENT_REQ_RANGE_LOW:
		spl := strings.SplitN(req.Header.Get("Range"), "-", 2)
		if len(spl) != 2 {
			return &value.Integer{Value: 0}, nil
		}
		low, err := strconv.ParseInt(spl[0], 10, 64)
		if err != nil {
			return value.Null, errors.WithStack(err)
		}
		return &value.Integer{Value: low}, nil
	case SEGMENTED_CACHING_COMPLETED:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Boolean{Value: false}, nil
	case SEGMENTED_CACHING_ERROR:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.String{Value: ""}, nil
	case SEGMENTED_CACHING_FAILED:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Boolean{Value: false}, nil
	case SEGMENTED_CACHING_IS_INNER_REQ:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Boolean{Value: false}, nil
	case SEGMENTED_CACHING_IS_OUTER_REQ:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Boolean{Value: true}, nil
	case SEGMENTED_CACHING_OBJ_COMPLETE_LENGTH:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Integer{Value: 0}, nil
	case SEGMENTED_CACHING_ROUNDED_REQ_RANGE_HIGH:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Integer{Value: 0}, nil
	case SEGMENTED_CACHING_ROUNDED_REQ_RANGE_LOW:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Integer{Value: 0}, nil
	case SEGMENTED_CACHING_TOTAL_BLOCKS:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Integer{Value: 0}, nil
	case FASTLY_INFO_REQUEST_ID:
		return v.ctx.RequestID, nil
	case FASTLY_DDOS_DETECTED:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Boolean{Value: false}, nil
	}

	// Look up shared variables
	if val, err := GetTCPInfoVariable(v.ctx, name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
	}
	if val, err := GetQuicVariable(v.ctx, name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
	}
	if val, err := GetTLSVariable(v.ctx, name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
	}
	if val, err := GetFastlyInfoVariable(v.ctx, name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
	}
	if val, err := GetWafVariables(v.ctx, name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
	}

	if val, err := v.getFromRegex(name); err != nil {
		return nil, err
	} else if val != nil {
		return val, nil
	}

	// If not found, also look up all scope value
	val, err := v.base.Get(s, name)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}
	return val, nil
}

func (v *LogScopeVariables) getFromRegex(name string) (value.Value, error) {
	// HTTP response header matching
	if match := responseHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		return &value.String{
			Value: v.ctx.Response.Header.Get(match[1]),
		}, nil
	}
	if match := backendRequestHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		return &value.String{
			Value: v.ctx.BackendRequest.Header.Get(match[1]),
		}, nil
	}
	return v.base.getFromRegex(name)
}

func (v *LogScopeVariables) Set(s context.Scope, name, operator string, val value.Value) error {
	switch name {
	case CLIENT_SOCKET_CONGESTION_ALGORITHM:
		if err := doAssign(v.ctx.ClientSocketCongestionAlgorithm, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case CLIENT_SOCKET_CWND:
		if err := doAssign(v.ctx.ClientSocketCwnd, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case CLIENT_SOCKET_PACE:
		if err := doAssign(v.ctx.ClientSocketPace, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case OBJ_GRACE:
		if err := doAssign(v.ctx.ObjectGrace, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case OBJ_TTL:
		if err := doAssign(v.ctx.ObjectTTL, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case RESP_RESPONSE:
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(v.ctx.Response.Body); err != nil {
			return errors.WithStack(err)
		}
		left := &value.String{Value: buf.String()}
		if err := doAssign(left, operator, val); err != nil {
			return errors.WithStack(err)
		}
		v.ctx.Response.Body = io.NopCloser(strings.NewReader(left.Value))
		return nil
	case RESP_STATUS:
		left := &value.Integer{Value: int64(v.ctx.Response.StatusCode)}
		if err := doAssign(left, operator, val); err != nil {
			return errors.WithStack(err)
		}
		v.ctx.Response.StatusCode = int(left.Value)
		v.ctx.Response.Status = http.StatusText(int(left.Value))
		return nil
	case SEGMENTED_CACHING_BLOCK_SIZE:
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
		if err := limitations.CheckProtectedHeader(match[1]); err != nil {
			return errors.WithStack(err)
		}
		v.ctx.Response.Header.Set(match[1], val.String())
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
	if err := limitations.CheckProtectedHeader(match[1]); err != nil {
		return errors.WithStack(err)
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
	if err := limitations.CheckProtectedHeader(match[1]); err != nil {
		return errors.WithStack(err)
	}
	v.ctx.Response.Header.Del(match[1])
	return nil
}
