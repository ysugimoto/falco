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

func (v *FetchScopeVariables) Get(s context.Scope, name string) (value.Value, error) {
	bereq := v.ctx.BackendRequest
	beresp := v.ctx.BackendResponse

	switch name {
	case "backend.conn.is_tls":
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
	case "backend.conn.tls_protocol":
		return &value.String{Value: "TLSv1.2"}, nil
	case "backend.socket.congestion_algorithm":
		return &value.String{Value: "cubic"}, nil
	case "backend.socket.cwnd":
		return &value.Integer{Value: 60}, nil
	case "backend.socket.tcpi_advmss",
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

	case "bereq.body_bytes_written":
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(bereq.Body); err != nil {
			return value.Null, errors.WithStack(err)
		}
		body := buf.Bytes()
		bereq.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
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

	case "beresp.handshake_time_to_origin_ms":
		// TODO: we need to implement backend communication without net/http package
		// because we have to know more raw socket informations
		return &value.Integer{Value: 100}, nil

	case "bereq.method":
		return &value.String{Value: bereq.Method}, nil
	case "bereq.proto":
		return &value.String{Value: bereq.Proto}, nil
	case "bereq.request":
		return v.Get(s, "bereq.method")
	case "bereq.url":
		url := bereq.URL.Path
		if v := bereq.URL.RawQuery; v != "" {
			url += "?" + v
		}
		if v := bereq.URL.RawFragment; v != "" {
			url += "#" + v
		}
		return &value.String{Value: url}, nil
	case "bereq.url.basename":
		return &value.String{
			Value: filepath.Base(bereq.URL.Path),
		}, nil
	case "bereq.url.dirname":
		return &value.String{
			Value: filepath.Dir(bereq.URL.Path),
		}, nil
	case "bereq.url.ext":
		ext := filepath.Ext(bereq.URL.Path)
		return &value.String{
			Value: strings.TrimPrefix(ext, "."),
		}, nil
	case "bereq.url.path":
		return &value.String{Value: bereq.URL.Path}, nil
	case "bereq.url.qs":
		return &value.String{Value: bereq.URL.RawQuery}, nil

	case "beresp.backend.alternate_ips":
		return &value.String{Value: ""}, nil
	case "beresp.backend.ip":
		return &value.String{Value: ""}, nil
	case "beresp.backend.name":
		return &value.String{Value: v.ctx.Backend.Value.Name.Value}, nil
	case "beresp.backend.port":
		for _, p := range v.ctx.Backend.Value.Properties {
			if p.Key.Value != "port" {
				continue
			}
			if s, ok := p.Value.(*ast.String); ok {
				return &value.String{Value: s.Value}, nil
			}
		}
		return &value.String{Value: ""}, nil
	case "beresp.backend.requests":
		return &value.Integer{Value: 1}, nil

	case "beresp.brotli":
		return v.ctx.BackendResponseBrotli, nil
	case "beresp.cacheable":
		return v.ctx.BackendResponseCacheable, nil
	case "beresp.do_esi":
		return v.ctx.BackendResponseDoESI, nil
	case "beresp.do_stream":
		return v.ctx.BackendResponseDoStream, nil
	case "beresp.grace":
		return v.ctx.BackendResponseGrace, nil
	case "beresp.gzip":
		return v.ctx.BackendResponseGzip, nil

	case "beresp.hipaa":
		return v.ctx.BackendResponseHipaa, nil
	case "beresp.pci":
		return v.ctx.BackendResponsePCI, nil

	case "beresp.proto":
		return &value.String{Value: "TLSv1.2"}, nil

	case "beresp.response":
		return v.ctx.BackendResponseResponse, nil
	case "beresp.saintmode":
		return v.ctx.BackendResponseSaintMode, nil
	case "beresp.stale_if_error":
		return v.ctx.BackendResponseStaleIfError, nil
	case "beresp.stale_while_revalidate":
		return v.ctx.BackendResponseStaleWhileRevalidate, nil
	case "beresp.status":
		return &value.Integer{Value: int64(beresp.StatusCode)}, nil
	case "beresp.ttl":
		return v.ctx.BackendResponseGzip, nil

	case "beresp.used_alternate_path_to_origin":
		// https://docs.fastly.com/en/guides/precision-path
		return &value.Boolean{Value: false}, nil

	case "client.socket.cwnd":
		return v.ctx.ClientSocketCwnd, nil

	case "client.socket.tcpi_snd_cwnd":
		return &value.Integer{Value: 0}, nil

	case "esi.allow_inside_cdata":
		return v.ctx.EsiAllowInsideCData, nil

	// Always false because simulator could not simulate origin-shielding
	case "fastly_info.is_cluster_shield":
		return &value.Boolean{Value: false}, nil

	// Always true because simulator could not simulate origin-shielding
	case "req.backend.is_origin":
		return &value.Boolean{Value: true}, nil
	// Digest ratio will return fixed value
	case "req.digest.ratio":
		return &value.Float{Value: 0.4}, nil

	case "req.esi":
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
				Value: v.ctx.Request.Header.Get(match[1]),
			}
		}
		spl := strings.SplitN(name, ":", 2)
		if strings.ToLower(spl[0]) != "cookie" {
			return &value.String{
				Value: v.ctx.Request.Header.Get(match[1]),
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
			Value: v.ctx.Request.Header.Get(match[1]),
		}
	}
	return nil
}

func (v *FetchScopeVariables) Set(s context.Scope, name, operator string, val value.Value) error {
	bereq := v.ctx.BackendRequest
	beresp := v.ctx.BackendResponse

	switch name {
	case "bereq.method":
		left := &value.String{Value: bereq.Method}
		if err := doAssign(left, operator, val); err != nil {
			return errors.WithStack(err)
		}
		bereq.Method = left.Value
		return nil
	case "bereq.request":
		return v.Set(s, "bereq.method", operator, val)
	case "bereq.url":
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
	case "beresp.brotli":
		if err := doAssign(v.ctx.BackendResponseBrotli, operator, val); err != nil {
			return errors.WithStack(err)
		}
		if v.ctx.BackendResponseBrotli.Value {
			v.ctx.BackendResponseGzip.Value = false
		}
		return nil
	case "beresp.cacheable":
		if err := doAssign(v.ctx.BackendResponseBrotli, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "beresp.do_esi":
		if err := doAssign(v.ctx.BackendResponseDoESI, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "beresp.do_stream":
		if err := doAssign(v.ctx.BackendResponseDoStream, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "beresp.grace":
		if err := doAssign(v.ctx.BackendResponseGrace, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "beresp.gzip":
		if err := doAssign(v.ctx.BackendResponseGzip, operator, val); err != nil {
			return errors.WithStack(err)
		}
		if v.ctx.BackendResponseGzip.Value {
			v.ctx.BackendResponseBrotli.Value = false
		}
		return nil
	case "beresp.hipaa":
		if err := doAssign(v.ctx.BackendResponseHipaa, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "beresp.pci":
		if err := doAssign(v.ctx.BackendResponsePCI, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "beresp.response":
		if err := doAssign(v.ctx.BackendResponseResponse, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "beresp.saintmode":
		if err := doAssign(v.ctx.BackendResponseSaintMode, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "beresp.stale_if_error":
		if err := doAssign(v.ctx.BackendResponseStaleIfError, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "beresp.stale_while_revalidate":
		if err := doAssign(v.ctx.BackendResponseStaleWhileRevalidate, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "beresp.status":
		left := &value.Integer{}
		if err := doAssign(left, operator, val); err != nil {
			return errors.WithStack(err)
		}
		beresp.StatusCode = int(left.Value)
		beresp.Status = http.StatusText(int(left.Value))
		return nil
	case "beresp.ttl":
		if err := doAssign(v.ctx.BackendResponseBrotli, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "client.socket.cwnd":
		if err := doAssign(v.ctx.ClientSocketCwnd, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "esi.allow_inside_cdata":
		if err := doAssign(v.ctx.EsiAllowInsideCData, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "req.esi":
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
