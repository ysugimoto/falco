package variable

import (
	"crypto/tls"
)

// Frequent occurrences string constant
const (
	PORT                     = "port"
	PURGE                    = "purge"
	FALCO_VIRTUAL_SERVICE_ID = "falco-virtual-service-id"
)

// Mapping from tls package ciphersuite name (IANA) to OpenSSL name
// see: src/crypto/tls/cipher_suites.go
// see: https://testssl.sh/openssl-iana.mapping.html
var CipherSuiteNameMap = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:                      "RC4-SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:                 "DES-CBC3-SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:                  "AES128-SHA",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:                  "AES256-SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:               "AES128-SHA256",
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:               "AES128-GCM-SHA256",
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:               "AES256-GCM-SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:              "ECDHE-ECDSA-RC4-SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:          "ECDHE-ECDSA-AES128-SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:          "ECDHE-ECDSA-AES256-SHA",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:                "ECDHE-RSA-RC4-SHA",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:           "ECDHE-RSA-DES-CBC3-SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:            "ECDHE-RSA-AES128-SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:            "ECDHE-RSA-AES256-SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:       "ECDHE-ECDSA-AES128-SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:         "ECDHE-RSA-AES128-SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         "ECDHE-RSA-AES128-GCM-SHA256",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       "ECDHE-ECDSA-AES128-GCM-SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         "ECDHE-RSA-AES256-GCM-SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       "ECDHE-ECDSA-AES256-GCM-SHA384",
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   "ECDHE-RSA-CHACHA20-POLY1305-OLD",
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: "ECDHE-ECDSA-CHACHA20-POLY1305-OLD",
	tls.TLS_AES_128_GCM_SHA256:                        "TLS_AES_128_GCM_SHA256",
	tls.TLS_AES_256_GCM_SHA384:                        "TLS_AES_256_GCM_SHA384",
	tls.TLS_CHACHA20_POLY1305_SHA256:                  "TLS_CHACHA20_POLY1305_SHA256",
	tls.TLS_FALLBACK_SCSV:                             "TLS_FALLBACK_SCSV",
}

// Mapping from tls package Version unt16 to string
var TLSVersionNameMap = map[uint16]string{
	tls.VersionTLS10: "TLSv1.0",
	tls.VersionTLS11: "TLSv1.1",
	tls.VersionTLS12: "TLSv1.2",
	tls.VersionTLS13: "TLSv1.3",
	// tls.VersionSSL30 is deprecated so we don't care it
}
