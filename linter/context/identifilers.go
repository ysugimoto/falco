package context

// Fastly predefined identifier list.
// we listed as possible as found in Fastly document site,
// but perhaps there are more builtin identifiers.
func builtinIdentifiers() map[string]struct{} {
	return map[string]struct{}{
		// use for backend.ssl_check_cert
		// https://developer.fastly.com/reference/vcl/declarations/backend/
		"always": {},
		"never":  {},

		// use for crypto.encrypt_xxx function cipher argument
		// https://developer.fastly.com/reference/vcl/functions/cryptographic/crypto-encrypt-hex/
		"aes128": {},
		"aes192": {},
		"aes256": {},

		// use for crypto.encrypt_xxx function mode argument
		// https://developer.fastly.com/reference/vcl/functions/cryptographic/crypto-encrypt-hex/
		"cbc": {},
		"ctr": {},

		// use for crypto.encrypt_xxx function padding argument
		// https://developer.fastly.com/reference/vcl/functions/cryptographic/crypto-encrypt-hex/
		"pkcs7": {},
		"nopad": {},

		// use for digest.rsa_verify and digest.ecdsa_verify function hash_method argument
		// https://developer.fastly.com/reference/vcl/functions/cryptographic/digest-rsa-verify/
		// https://www.fastly.com/documentation/reference/vcl/functions/cryptographic/digest-ecdsa-verify/
		"default": {},
		"sha256":  {},
		"sha384":  {},
		"sha512":  {},
		"sha1":    {},

		// use for digest.rsa_verify and digest.ecdsa_verify function base64_method argument
		// https://developer.fastly.com/reference/vcl/functions/cryptographic/digest-rsa-verify/
		// https://www.fastly.com/documentation/reference/vcl/functions/cryptographic/digest-ecdsa-verify/
		"standard":  {},
		"url":       {},
		"url_nopad": {},

		// use for digest.ecdsa_verify function digest argument
		// https://www.fastly.com/documentation/reference/vcl/functions/cryptographic/digest-ecdsa-verify/
		"der": {},
		"jwt": {},

		// use for setcookie.get_value_by_name argument of ID
		"req":    {},
		"bereq":  {},
		"obj":    {},
		"beresp": {},
		"resp":   {},
	}
}
