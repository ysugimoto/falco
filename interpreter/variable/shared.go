package variable

import (
	"fmt"
	"time"

	"github.com/k0kubun/pp"
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/limitations"
	"github.com/ysugimoto/falco/interpreter/value"
)

func GetFastlyInfoVariable(ctx *context.Context, name string) (value.Value, error) {
	switch name {
	case FASTLY_INFO_H2_IS_PUSH:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.Boolean{Value: false}, nil
	case FASTLY_INFO_H2_STREAM_ID:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.Integer{Value: 1}, nil
	}
	return nil, nil
}

func GetQuicVariable(ctx *context.Context, name string) (value.Value, error) {
	switch name {
	// QUIC related values return zero
	case QUIC_CC_CWND,
		QUIC_CC_SSTHRESH,
		QUIC_NUM_BYTES_RECEIVED,
		QUIC_NUM_BYTES_SENT,
		QUIC_NUM_PACKETS_ACK_RECEIVED,
		QUIC_NUM_PACKETS_DECRYPTION_FAILED,
		QUIC_NUM_PACKETS_LATE_ACKED,
		QUIC_NUM_PACKETS_LOST,
		QUIC_NUM_PACKETS_RECEIVED,
		QUIC_NUM_PACKETS_SENT,
		QUIC_RTT_LATEST,
		QUIC_RTT_MINIMUM,
		QUIC_RTT_SMOOTHED,
		QUIC_RTT_VARIANCE:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.Integer{Value: 0}, nil
	}
	return nil, nil
}

func GetTCPInfoVariable(ctx *context.Context, name string) (value.Value, error) {
	switch name {
	// We treat that tcp_info is disabled so following value is zero
	case CLIENT_SOCKET_TCP_INFO:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.Boolean{Value: false}, nil
	case CLIENT_SOCKET_TCPI_ADVMSS,
		CLIENT_SOCKET_TCPI_BYTES_ACKED,
		CLIENT_SOCKET_TCPI_BYTES_RECEIVED,
		CLIENT_SOCKET_TCPI_DATA_SEGS_IN,
		CLIENT_SOCKET_TCPI_DATA_SEGS_OUT,
		CLIENT_SOCKET_TCPI_DELIVERY_RATE,
		CLIENT_SOCKET_TCPI_DELTA_RETRANS,
		CLIENT_SOCKET_TCPI_LAST_DATA_SENT,
		CLIENT_SOCKET_TCPI_MAX_PACING_RATE,
		CLIENT_SOCKET_TCPI_MIN_RTT,
		CLIENT_SOCKET_TCPI_NOTSENT_BYTES,
		CLIENT_SOCKET_TCPI_PACING_RATE,
		CLIENT_SOCKET_TCPI_PMTU,
		CLIENT_SOCKET_TCPI_RCV_MSS,
		CLIENT_SOCKET_TCPI_RCV_RTT,
		CLIENT_SOCKET_TCPI_RCV_SPACE,
		CLIENT_SOCKET_TCPI_RCV_SSTHRESH,
		CLIENT_SOCKET_TCPI_REORDERING,
		CLIENT_SOCKET_TCPI_RTT,
		CLIENT_SOCKET_TCPI_RTTVAR,
		CLIENT_SOCKET_TCPI_SEGS_IN,
		CLIENT_SOCKET_TCPI_SEGS_OUT,
		CLIENT_SOCKET_TCPI_SND_CWND,
		CLIENT_SOCKET_TCPI_SND_MSS,
		CLIENT_SOCKET_TCPI_SND_SSTHRESH,
		CLIENT_SOCKET_TCPI_TOTAL_RETRANS:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.Integer{Value: 0}, nil
	case TLS_CLIENT_CERTIFICATE_DN,
		TLS_CLIENT_CERTIFICATE_ISSUER_DN,
		TLS_CLIENT_CERTIFICATE_RAW_CERTIFICATE_B64,
		TLS_CLIENT_CERTIFICATE_SERIAL_NUMBER:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.String{Value: ""}, nil

	case TLS_CLIENT_CERTIFICATE_IS_CERT_BAD,
		TLS_CLIENT_CERTIFICATE_IS_CERT_EXPIRED,
		TLS_CLIENT_CERTIFICATE_IS_CERT_MISSING,
		TLS_CLIENT_CERTIFICATE_IS_CERT_REVOKED,
		TLS_CLIENT_CERTIFICATE_IS_CERT_UNKNOWN,
		TLS_CLIENT_CERTIFICATE_IS_UNKNOWN_CA:
		if v := lookupOverride(ctx, name); v != nil {
			pp.Println(name)
			return v, nil
		}
		return &value.Boolean{Value: false}, nil
	case TLS_CLIENT_CERTIFICATE_IS_VERIFIED:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.Boolean{Value: true}, nil

	case TLS_CLIENT_CERTIFICATE_NOT_BEFORE:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.Time{Value: time.Now().Add(-24 * time.Hour)}, nil
	case TLS_CLIENT_CERTIFICATE_NOT_AFTER:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.Time{Value: time.Now().Add(-24 * time.Hour).Add(24 * time.Hour * 365)}, nil
	}

	return nil, nil
}

// TODO: consider we need to construct TLS server manually instead of net/http server
// Temporarily return tentative data found in Fastly fiddle
func GetTLSVariable(ctx *context.Context, name string) (value.Value, error) {
	s := ctx.Request.TLS

	switch name {
	case TLS_CLIENT_CIPHER:
		if s == nil {
			return &value.String{Value: ""}, nil
		} else {
			return &value.String{Value: CipherSuiteNameMap[s.CipherSuite]}, nil
		}

	case TLS_CLIENT_CIPHERS_LIST:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.String{
			// nolint: lll
			Value: "130213031301C02FC02BC030C02C009EC0270067C028006B00A3009FCCA9CCA8CCAAC0AFC0ADC0A3C09FC05DC061C057C05300A2C0AEC0ACC0A2C09EC05CC060C056C052C024006AC0230040C00AC01400390038C009C01300330032009DC0A1C09DC051009CC0A0C09CC050003D003C0035002F00FF",
		}, nil
	case TLS_CLIENT_CIPHERS_LIST_SHA:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.String{Value: "JZtiTn8H/ntxORk+XXvU2EvNoz8="}, nil
	case TLS_CLIENT_CIPHERS_LIST_TXT:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.String{
			// nolint: lll
			Value: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:TLS_ECDHE_ECDSA_WITH_AES_256_CCM:TLS_DHE_RSA_WITH_AES_256_CCM_8:TLS_DHE_RSA_WITH_AES_256_CCM:TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384:TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384:TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384:TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:TLS_ECDHE_ECDSA_WITH_AES_128_CCM:TLS_DHE_RSA_WITH_AES_128_CCM_8:TLS_DHE_RSA_WITH_AES_128_CCM:TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256:TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_DHE_RSA_WITH_AES_256_CBC_SHA:TLS_DHE_DSS_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_DHE_RSA_WITH_AES_128_CBC_SHA:TLS_DHE_DSS_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_256_CCM_8:TLS_RSA_WITH_AES_256_CCM:TLS_RSA_WITH_ARIA_256_GCM_SHA384:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_128_CCM_8:TLS_RSA_WITH_AES_128_CCM:TLS_RSA_WITH_ARIA_128_GCM_SHA256:TLS_RSA_WITH_AES_256_CBC_SHA256:TLS_RSA_WITH_AES_128_CBC_SHA256:TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
		}, nil
	case TLS_CLIENT_CIPHERS_SHA:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.String{Value: "+7dB1w3Ov9S4Ct3HG3Qed68pSko="}, nil
	case TLS_CLIENT_HANDSHAKE_SENT_BYTES:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.Integer{Value: 4759}, nil
	case TLS_CLIENT_IANA_CHOSEN_CIPHER_ID:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.Integer{Value: 49199}, nil
	case TLS_CLIENT_JA3_MD5:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.String{Value: "582a3b42ab84f78a5b376b1e29d6d367"}, nil
	case TLS_CLIENT_JA4:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		// Use fastly fiddle value
		// https://fiddle.fastly.dev/fiddle/67edbddf
		// Actually we may be able to calculate, algorithm is here:
		// https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
		return &value.String{Value: "t13d5911h2_a33745022dd6_1f22a2ca17c4"}, nil
	case TLS_CLIENT_PROTOCOL:
		if s == nil {
			return &value.String{Value: ""}, nil
		}
		return &value.String{Value: TLSVersionNameMap[s.Version]}, nil

	case TLS_CLIENT_SERVERNAME,
		TLS_CLIENT_TLSEXTS_LIST,
		TLS_CLIENT_TLSEXTS_LIST_SHA,
		TLS_CLIENT_TLSEXTS_LIST_TXT,
		TLS_CLIENT_TLSEXTS_SHA:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.String{Value: ""}, nil

		// We could not simulate following variable, return with zero/empty
	case TRANSPORT_BW_ESTIMATE:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.Integer{Value: 0}, nil
	case TRANSPORT_TYPE:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		// TODO: will be "quic" if we have support quic protocol
		return &value.String{Value: "tcp"}, nil
	}
	return nil, nil
}

// Shared WAF relation variables.
// Note that we could not simulate Fastly legacy waf behavior, returns fake values.
// If user write logic which corresponds to following value, process may be unexpected.
func GetWafVariables(ctx *context.Context, name string) (value.Value, error) {
	switch name {
	case WAF_ANOMALY_SCORE:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return ctx.WafAnomalyScore, nil
	case WAF_BLOCKED:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return ctx.WafBlocked, nil
	case WAF_COUNTER:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return ctx.WafCounter, nil
	case WAF_EXECUTED:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return ctx.WafExecuted, nil
	case WAF_FAILURES:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return &value.Integer{Value: 0}, nil
	case WAF_HTTP_VIOLATION_SCORE:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return ctx.WafHttpViolationScore, nil
	case WAF_INBOUND_ANOMALY_SCORE:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return ctx.WafInboundAnomalyScore, nil
	case WAF_LFI_SCORE:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return ctx.WafLFIScore, nil
	case WAF_LOGDATA:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return ctx.WafLogData, nil
	case WAF_LOGGED:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return ctx.WafLogged, nil
	case WAF_MESSAGE:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return ctx.WafMessage, nil
	case WAF_PASSED:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return ctx.WafPassed, nil
	case WAF_PHP_INJECTION_SCORE:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return ctx.WafPHPInjectionScore, nil
	case WAF_RCE_SCORE:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return ctx.WafRCEScore, nil
	case WAF_RFI_SCORE:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return ctx.WafRFIScore, nil
	case WAF_RULE_ID:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return ctx.WafRuleId, nil
	case WAF_SESSION_FIXATION_SCORE:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return ctx.WafSessionFixationScore, nil
	case WAF_SEVERITY:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return ctx.WafSeverity, nil
	case WAF_XSS_SCORE:
		if v := lookupOverride(ctx, name); v != nil {
			return v, nil
		}
		return ctx.WafXSSScore, nil
	}
	return nil, nil
}

func SetBackendRequestHeader(ctx *context.Context, name string, val value.Value) (bool, error) {
	if match := backendRequestHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		if err := limitations.CheckProtectedHeader(match[1]); err != nil {
			return true, errors.WithStack(err)
		}
		setRequestHeaderValue(ctx.BackendRequest, match[1], val)
		return true, nil
	}
	return false, nil
}

func SetWafVariables(ctx *context.Context, name, operator string, val value.Value) (bool, error) {
	switch name {
	case WAF_ANOMALY_SCORE:
		if err := doAssign(ctx.WafAnomalyScore, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case WAF_BLOCKED:
		if err := doAssign(ctx.WafBlocked, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case WAF_COUNTER:
		if err := doAssign(ctx.WafCounter, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case WAF_EXECUTED:
		if err := doAssign(ctx.WafExecuted, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case WAF_HTTP_VIOLATION_SCORE:
		if err := doAssign(ctx.WafHttpViolationScore, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case WAF_INBOUND_ANOMALY_SCORE:
		if err := doAssign(ctx.WafInboundAnomalyScore, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case WAF_LFI_SCORE:
		if err := doAssign(ctx.WafLFIScore, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case WAF_LOGDATA:
		if err := doAssign(ctx.WafLogData, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case WAF_LOGGED:
		if err := doAssign(ctx.WafLogged, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case WAF_MESSAGE:
		if err := doAssign(ctx.WafMessage, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case WAF_PASSED:
		if err := doAssign(ctx.WafPassed, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case WAF_RFI_SCORE:
		if err := doAssign(ctx.WafRFIScore, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case WAF_RULE_ID:
		if err := doAssign(ctx.WafRuleId, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case WAF_SESSION_FIXATION_SCORE:
		if err := doAssign(ctx.WafSessionFixationScore, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case WAF_SEVERITY:
		if err := doAssign(ctx.WafSeverity, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case WAF_XSS_SCORE:
		if err := doAssign(ctx.WafXSSScore, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case WAF_PHP_INJECTION_SCORE:
		if err := doAssign(ctx.WafPHPInjectionScore, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case WAF_RCE_SCORE:
		if err := doAssign(ctx.WafRCEScore, operator, val); err != nil {
			return true, errors.WithStack(err)
		}
		return true, nil
	case WAF_FAILURES:
		return false, errors.WithStack(fmt.Errorf(
			"Variable %s could not set value", name,
		))
	}
	return false, nil
}
