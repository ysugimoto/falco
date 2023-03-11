package variable

import (
	"crypto/tls"
	"fmt"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func GetFastlyInfoVairable(name string) (value.Value, error) {
	switch name {
	case "fastly_info.h2.is_push":
		return &value.Boolean{Value: false}, nil
	case "fastly_info.h2.stream_id":
		return &value.Integer{Value: 1}, nil
	}
	return nil, nil
}

func GetQuicVariable(name string) (value.Value, error) {
	switch name {
	// QUIC related values return zero
	case "quic.cc.cwnd",
		"quic.cc.ssthresh",
		"quic.num_bytes.received",
		"quic.num_bytes.sent",
		"quic.num_packets.ack_received",
		"quic.num_packets.decryption_failed",
		"quic.num_packets.late_acked",
		"quic.num_packets.lost",
		"quic.num_packets.received",
		"quic.num_packets.sent",
		"quic.rtt.latest",
		"quic.rtt.minimum",
		"quic.rtt.smoothed",
		"quic.rtt.variance":
		return &value.Integer{Value: 0}, nil
	}
	return nil, nil
}

func GetTCPInfoVariable(name string) (value.Value, error) {
	switch name {
	// We treat that tcp_info is disabled so following value is zero
	case "client.socket.tcp_info":
		return &value.Boolean{Value: false}, nil
	case "client.socket.tcpi_advmss",
		"client.socket.tcpi_bytes_acked",
		"client.socket.tcpi_bytes_received",
		"client.socket.tcpi_data_segs_in",
		"client.socket.tcpi_data_segs_out",
		"client.socket.tcpi_delivery_rate",
		"client.socket.tcpi_delta_retrans",
		"client.socket.tcpi_last_data_sent",
		"client.socket.tcpi_max_pacing_rate",
		"client.socket.tcpi_min_rtt",
		"client.socket.tcpi_notsent_bytes",
		"client.socket.tcpi_pacing_rate",
		"client.socket.tcpi_pmtu",
		"client.socket.tcpi_rcv_mss",
		"client.socket.tcpi_rcv_rtt",
		"client.socket.tcpi_rcv_space",
		"client.socket.tcpi_rcv_ssthresh",
		"client.socket.tcpi_reordering",
		"client.socket.tcpi_rtt",
		"client.socket.tcpi_rttvar",
		"client.socket.tcpi_segs_in",
		"client.socket.tcpi_segs_out",
		"client.socket.tcpi_snd_cwnd",
		"client.socket.tcpi_snd_mss",
		"client.socket.tcpi_snd_ssthresh",
		"client.socket.tcpi_total_retrans":
		return &value.Integer{Value: 0}, nil
	}

	return nil, nil
}

// TODO: consider we need to construct TLS server manually instead of net/http server
// Temporaly return our environment data in Fastly fiddle
func GetTLSVariable(s *tls.ConnectionState, name string) (value.Value, error) {
	switch name {
	case "tls.client.cipher":
		if s == nil {
			return &value.String{Value: ""}, nil
		} else {
			return &value.String{Value: CipherSuiteNameMap[s.CipherSuite]}, nil
		}

	case "tls.client.ciphers_list":
		return &value.String{
			// nolint: lll
			Value: "130213031301C02FC02BC030C02C009EC0270067C028006B00A3009FCCA9CCA8CCAAC0AFC0ADC0A3C09FC05DC061C057C05300A2C0AEC0ACC0A2C09EC05CC060C056C052C024006AC0230040C00AC01400390038C009C01300330032009DC0A1C09DC051009CC0A0C09CC050003D003C0035002F00FF",
		}, nil
	case "tls.client.ciphers_list_sha":
		return &value.String{Value: "JZtiTn8H/ntxORk+XXvU2EvNoz8="}, nil
	case "tls.client.ciphers_list_txt":
		return &value.String{
			// nolint: lll
			Value: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:TLS_ECDHE_ECDSA_WITH_AES_256_CCM:TLS_DHE_RSA_WITH_AES_256_CCM_8:TLS_DHE_RSA_WITH_AES_256_CCM:TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384:TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384:TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384:TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:TLS_ECDHE_ECDSA_WITH_AES_128_CCM:TLS_DHE_RSA_WITH_AES_128_CCM_8:TLS_DHE_RSA_WITH_AES_128_CCM:TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256:TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_DHE_RSA_WITH_AES_256_CBC_SHA:TLS_DHE_DSS_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_DHE_RSA_WITH_AES_128_CBC_SHA:TLS_DHE_DSS_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_256_CCM_8:TLS_RSA_WITH_AES_256_CCM:TLS_RSA_WITH_ARIA_256_GCM_SHA384:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_128_CCM_8:TLS_RSA_WITH_AES_128_CCM:TLS_RSA_WITH_ARIA_128_GCM_SHA256:TLS_RSA_WITH_AES_256_CBC_SHA256:TLS_RSA_WITH_AES_128_CBC_SHA256:TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
		}, nil
	case "tls.client.ciphers_sha":
		return &value.String{Value: "+7dB1w3Ov9S4Ct3HG3Qed68pSko="}, nil
	case "tls.client.handshake_sent_bytes":
		return &value.Integer{Value: 4759}, nil
	case "tls.client.iana_chosen_cipher_id":
		return &value.Integer{Value: 49199}, nil
	case "tls.client.ja3_md5":
		return &value.String{Value: "582a3b42ab84f78a5b376b1e29d6d367"}, nil
	case "tls.client.protocol":
		if s == nil {
			return &value.String{Value: ""}, nil
		}
		return &value.String{Value: TLSVersionNameMap[s.Version]}, nil

	case "tls.client.servername",
		"tls.client.tlsexts_list",
		"tls.client.tlsexts_list_sha",
		"tls.client.tlsexts_list_txt",
		"tls.client.tlsexts_sha":
		return &value.String{Value: ""}, nil

		// We could not simulate following variable, return with zero/empty
	case "transport.bw_estimate":
		return &value.Integer{Value: 0}, nil
	case "transport.type":
		// TODO: will be "quic" if we have support quic protocol
		return &value.String{Value: "tcp"}, nil
	}
	return nil, nil
}

// Shared WAF relation variables.
// Note that we could not sumulate Fastly legacy waf behavior, returns fake values.
// If user write logic which corresponds to following value, process may be unexpected.
func GetWafVariables(ctx *context.Context, name string) (value.Value, error) {
	switch name {
	case "waf.anomaly_score":
		return ctx.WafAnomalyScore, nil
	case "waf.blocked":
		return ctx.WafBlocked, nil
	case "waf.counter":
		return ctx.WafCounter, nil
	case "waf.executed":
		return ctx.WafExecuted, nil
	case "waf.failures":
		return &value.Integer{Value: 0}, nil
	case "waf.http_violation_score":
		return ctx.WafHttpViolationScore, nil
	case "waf.inbound_anomaly_score":
		return ctx.WafInbouldAnomalyScore, nil
	case "waf.lfi_score":
		return ctx.WafLFIScore, nil
	case "waf.logdata":
		return ctx.WafLogData, nil
	case "waf.logged":
		return ctx.WafLogged, nil
	case "waf.message":
		return ctx.WafMessage, nil
	case "waf.passed":
		return ctx.WafPassed, nil
	case "waf.php_injection_score":
		return &value.Integer{Value: 0}, nil
	case "waf.rce_score":
		return &value.Integer{Value: 0}, nil
	case "waf.rfi_score":
		return ctx.WafRFIScore, nil
	case "waf.rule_id":
		return ctx.WafRuleId, nil
	case "waf.session_fixation_score":
		return ctx.WafSesionFixationScore, nil
	case "waf.severity":
		return ctx.WafSeverity, nil
	case "waf.xss_score":
		return ctx.WafXSSScore, nil
	}
	return nil, nil
}

func SetWafVariables(ctx *context.Context, name, operator string, val value.Value) (bool, error) {
	switch name {
	case "waf.anomaly_score":
		if err := doAssign(ctx.WafAnomalyScore, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case "waf.blocked":
		if err := doAssign(ctx.WafBlocked, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case "waf.counter":
		if err := doAssign(ctx.WafCounter, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case "waf.executed":
		if err := doAssign(ctx.WafExecuted, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case "waf.http_violation_score":
		if err := doAssign(ctx.WafHttpViolationScore, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case "waf.inbound_anomaly_score":
		if err := doAssign(ctx.WafInbouldAnomalyScore, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case "waf.lfi_score":
		if err := doAssign(ctx.WafLFIScore, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case "waf.logdata":
		if err := doAssign(ctx.WafLogData, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case "waf.logged":
		if err := doAssign(ctx.WafLogged, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case "waf.message":
		if err := doAssign(ctx.WafMessage, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case "waf.passed":
		if err := doAssign(ctx.WafPassed, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case "waf.rfi_score":
		if err := doAssign(ctx.WafRFIScore, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case "waf.rule_id":
		if err := doAssign(ctx.WafRuleId, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case "waf.session_fixation_score":
		if err := doAssign(ctx.WafSesionFixationScore, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case "waf.severity":
		if err := doAssign(ctx.WafSeverity, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case "waf.xss_score":
		if err := doAssign(ctx.WafXSSScore, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case "waf.failures",
		"waf.php_injection_score",
		"waf.rce_score":
		return false, errors.WithStack(fmt.Errorf(
			"Variable %s could not set value", name,
		))
	}
	return false, nil
}
