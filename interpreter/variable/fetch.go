package variable

import (
	"bytes"
	"io"
	"strings"

	"net/http"
	"net/url"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

type FetchScopeVariables struct {
	Variable
	base *AllScopeVariables
	ctx  *context.Context
}

func NewFetchScopeVariables(ctx *context.Context) *FetchScopeVariables {
	return &FetchScopeVariables{
		base: NewAllScopeVariables(ctx),
		ctx:  ctx,
	}
}

// nolint: funlen,gocognit,gocyclo
func (v *FetchScopeVariables) Get(s context.Scope, name string) (value.Value, error) {
	bereq := v.ctx.BackendRequest
	beresp := v.ctx.BackendResponse

	switch name {
	case BACKEND_CONN_IS_TLS:
		var isTLS bool
		for _, p := range v.ctx.Backend.Value.Properties {
			if p.Key.Value != "ssl" {
				continue
			}
			if b, ok := p.Value.(*ast.Boolean); ok {
				isTLS = b.Value
				break
			}
		}
		return &value.Boolean{Value: isTLS}, nil
	case BACKEND_CONN_TLS_PROTOCOL:
		return &value.String{Value: "TLSv1.2"}, nil
	case BACKEND_SOCKET_CONGESTION_ALGORITHM:
		return &value.String{Value: "cubic"}, nil
	case BACKEND_SOCKET_CWND:
		return &value.Integer{Value: 60}, nil
	case BACKEND_SOCKET_TCPI_ADVMSS,
		"backend.socket.tcpi_bytes_acked",
		"backend.socket.tcpi_bytes_received",
		"backend.socket.tcpi_data_segs_in",
		"backend.socket.tcpi_data_segs_out",
		"backend.socket.tcpi_delivery_rate",
		"backend.socket.tcpi_delta_retrans",
		"backend.socket.tcpi_last_data_sent",
		"backend.socket.tcpi_max_pacing_rate",
		"backend.socket.tcpi_min_rtt",
		"backend.socket.tcpi_notsent_bytes",
		"backend.socket.tcpi_pacing_rate",
		"backend.socket.tcpi_pmtu",
		"backend.socket.tcpi_rcv_mss",
		"backend.socket.tcpi_rcv_rtt",
		"backend.socket.tcpi_rcv_space",
		"backend.socket.tcpi_rcv_ssthresh",
		"backend.socket.tcpi_reordering",
		"backend.socket.tcpi_rtt",
		"backend.socket.tcpi_rttvar",
		"backend.socket.tcpi_segs_in",
		"backend.socket.tcpi_segs_out",
		"backend.socket.tcpi_snd_cwnd",
		"backend.socket.tcpi_snd_mss",
		"backend.socket.tcpi_snd_ssthresh",
		"backend.socket.tcpi_total_retrans":
		return &value.Integer{Value: 0}, nil

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

	case BERESP_HANDSHAKE_TIME_TO_ORIGIN_MS:
		// TODO: we need to implement backend communication without net/http package
		// because we have to know more raw socket informations
		return &value.Integer{Value: 100}, nil

	case BEREQ_METHOD:
		return &value.String{Value: bereq.Method}, nil
	case BEREQ_PROTO:
		return &value.String{Value: bereq.Proto}, nil
	case BEREQ_REQUEST:
		return v.Get(s, "bereq.method")
	case BEREQ_URL:
		u := bereq.URL.Path
		if v := bereq.URL.RawQuery; v != "" {
			u += "?" + v
		}
		if v := bereq.URL.RawFragment; v != "" {
			u += "#" + v
		}
		return &value.String{Value: u}, nil
	case BEREQ_URL_BASENAME:
		return &value.String{
			Value: filepath.Base(bereq.URL.Path),
		}, nil
	case BEREQ_URL_DIRNAME:
		return &value.String{
			Value: filepath.Dir(bereq.URL.Path),
		}, nil
	case BEREQ_URL_EXT:
		ext := filepath.Ext(bereq.URL.Path)
		return &value.String{
			Value: strings.TrimPrefix(ext, "."),
		}, nil
	case BEREQ_URL_PATH:
		return &value.String{Value: bereq.URL.Path}, nil
	case BEREQ_URL_QS:
		return &value.String{Value: bereq.URL.RawQuery}, nil

	case BERESP_BACKEND_ALTERNATE_IPS:
		return &value.String{Value: ""}, nil
	case BERESP_BACKEND_IP:
		return &value.String{Value: ""}, nil
	case BERESP_BACKEND_NAME:
		return &value.String{Value: v.ctx.Backend.Value.Name.Value}, nil
	case BERESP_BACKEND_PORT:
		for _, p := range v.ctx.Backend.Value.Properties {
			if p.Key.Value != "port" {
				continue
			}
			if s, ok := p.Value.(*ast.String); ok {
				return &value.String{Value: s.Value}, nil
			}
		}
		return &value.String{Value: ""}, nil
	case BERESP_BACKEND_REQUESTS:
		return &value.Integer{Value: 1}, nil

	case BERESP_BROTLI:
		return v.ctx.BackendResponseBrotli, nil
	case BERESP_CACHEABLE:
		return v.ctx.BackendResponseCacheable, nil
	case BERESP_DO_ESI:
		return v.ctx.BackendResponseDoESI, nil
	case BERESP_DO_STREAM:
		return v.ctx.BackendResponseDoStream, nil
	case BERESP_GRACE:
		return v.ctx.BackendResponseGrace, nil
	case BERESP_GZIP:
		return v.ctx.BackendResponseGzip, nil

	case BERESP_HIPAA:
		return v.ctx.BackendResponseHipaa, nil
	case BERESP_PCI:
		return v.ctx.BackendResponsePCI, nil

	case BERESP_PROTO:
		return &value.String{Value: "TLSv1.2"}, nil

	case BERESP_RESPONSE:
		return v.ctx.BackendResponseResponse, nil
	case BERESP_SAINTMODE:
		return v.ctx.BackendResponseSaintMode, nil
	case BERESP_STALE_IF_ERROR:
		return v.ctx.BackendResponseStaleIfError, nil
	case BERESP_STALE_WHILE_REVALIDATE:
		return v.ctx.BackendResponseStaleWhileRevalidate, nil
	case BERESP_STATUS:
		return &value.Integer{Value: int64(beresp.StatusCode)}, nil
	case BERESP_TTL:
		return v.ctx.BackendResponseGzip, nil

	case BERESP_USED_ALTERNATE_PATH_TO_ORIGIN:
		// https://docs.fastly.com/en/guides/precision-path
		return &value.Boolean{Value: false}, nil

	case CLIENT_SOCKET_CWND:
		return v.ctx.ClientSocketCwnd, nil

	case CLIENT_SOCKET_TCPI_SND_CWND:
		return &value.Integer{Value: 0}, nil

	case ESI_ALLOW_INSIDE_CDATA:
		return v.ctx.EsiAllowInsideCData, nil

	// Always false because simulator could not simulate origin-shielding
	case FASTLY_INFO_IS_CLUSTER_SHIELD:
		return &value.Boolean{Value: false}, nil

	// Always true because simulator could not simulate origin-shielding
	case REQ_BACKEND_IS_ORIGIN:
		return &value.Boolean{Value: true}, nil
	// Digest ratio will return fixed value
	case REQ_DIGEST_RATIO:
		return &value.Float{Value: 0.4}, nil

	case REQ_ESI:
		return v.ctx.EnableSSI, nil
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

func (v *FetchScopeVariables) getFromRegex(name string) value.Value {
	// HTTP request header matching
	if match := backendRequestHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		// If name is Cookie, header name can contain ":" with cookie name
		if !strings.Contains(name, ":") {
			return &value.String{
				Value: v.ctx.BackendRequest.Header.Get(match[1]),
			}
		}
		spl := strings.SplitN(name, ":", 2)
		if !strings.EqualFold(spl[0], "cookie") {
			return &value.String{
				Value: v.ctx.BackendRequest.Header.Get(match[1]),
			}
		}

		for _, c := range v.ctx.BackendRequest.Cookies() {
			if c.Name == spl[1] {
				return &value.String{Value: c.Value}
			}
		}
		return &value.String{Value: ""}
	}

	if match := backendResponseHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		return &value.String{
			Value: v.ctx.BackendResponse.Header.Get(match[1]),
		}
	}
	return v.base.getFromRegex(name)
}

// nolint: funlen, gocognit
func (v *FetchScopeVariables) Set(s context.Scope, name, operator string, val value.Value) error {
	bereq := v.ctx.BackendRequest
	beresp := v.ctx.BackendResponse

	switch name {
	case BEREQ_METHOD:
		left := &value.String{Value: bereq.Method}
		if err := doAssign(left, operator, val); err != nil {
			return errors.WithStack(err)
		}
		bereq.Method = left.Value
		return nil
	case BEREQ_REQUEST:
		return v.Set(s, "bereq.method", operator, val)
	case BEREQ_URL:
		u := bereq.URL.Path
		if query := bereq.URL.RawQuery; query != "" {
			u += "?" + query
		}
		if fragment := bereq.URL.RawFragment; fragment != "" {
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
		bereq.URL.Path = parsed.Path
		bereq.URL.RawQuery = parsed.RawPath
		bereq.URL.RawFragment = parsed.RawFragment
		return nil
	case BERESP_BROTLI:
		if err := doAssign(v.ctx.BackendResponseBrotli, operator, val); err != nil {
			return errors.WithStack(err)
		}
		if v.ctx.BackendResponseBrotli.Value {
			v.ctx.BackendResponseGzip.Value = false
		}
		return nil
	case BERESP_CACHEABLE:
		if err := doAssign(v.ctx.BackendResponseBrotli, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case BERESP_DO_ESI:
		if err := doAssign(v.ctx.BackendResponseDoESI, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case BERESP_DO_STREAM:
		if err := doAssign(v.ctx.BackendResponseDoStream, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case BERESP_GRACE:
		if err := doAssign(v.ctx.BackendResponseGrace, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case BERESP_GZIP:
		if err := doAssign(v.ctx.BackendResponseGzip, operator, val); err != nil {
			return errors.WithStack(err)
		}
		if v.ctx.BackendResponseGzip.Value {
			v.ctx.BackendResponseBrotli.Value = false
		}
		return nil
	case BERESP_HIPAA:
		if err := doAssign(v.ctx.BackendResponseHipaa, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case BERESP_PCI:
		if err := doAssign(v.ctx.BackendResponsePCI, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case BERESP_RESPONSE:
		if err := doAssign(v.ctx.BackendResponseResponse, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case BERESP_SAINTMODE:
		if err := doAssign(v.ctx.BackendResponseSaintMode, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case BERESP_STALE_IF_ERROR:
		if err := doAssign(v.ctx.BackendResponseStaleIfError, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case BERESP_STALE_WHILE_REVALIDATE:
		if err := doAssign(v.ctx.BackendResponseStaleWhileRevalidate, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case BERESP_STATUS:
		left := &value.Integer{}
		if err := doAssign(left, operator, val); err != nil {
			return errors.WithStack(err)
		}
		beresp.StatusCode = int(left.Value)
		beresp.Status = http.StatusText(int(left.Value))
		return nil
	case BERESP_TTL:
		if err := doAssign(v.ctx.BackendResponseBrotli, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case CLIENT_SOCKET_CWND:
		if err := doAssign(v.ctx.ClientSocketCwnd, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case ESI_ALLOW_INSIDE_CDATA:
		if err := doAssign(v.ctx.EsiAllowInsideCData, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case REQ_ESI:
		if err := doAssign(v.ctx.EnableSSI, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	}

	if match := backendRequestHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		bereq.Header.Set(match[1], val.String())
		return nil
	}
	if match := backendResponseHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		beresp.Header.Set(match[1], val.String())
		return nil
	}

	// If not found, pass to all scope value
	return v.base.Set(s, name, operator, val)
}

func (v *FetchScopeVariables) Add(s context.Scope, name string, val value.Value) error {
	// Add statement could be use only for HTTP header
	if match := backendRequestHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		v.ctx.BackendRequest.Header.Add(match[1], val.String())
	} else if match := backendResponseHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		v.ctx.BackendResponse.Header.Add(match[1], val.String())
	} else {
		return v.base.Add(s, name, val)
	}

	return nil
}

func (v *FetchScopeVariables) Unset(s context.Scope, name string) error {
	match := backendRequestHttpHeaderRegex.FindStringSubmatch(name)
	if match == nil {
		// Nothing values to be enable to unset in PASS, pass to base
		return v.base.Unset(s, name)
	}
	v.ctx.BackendRequest.Header.Del(match[1])
	return nil
}