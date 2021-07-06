package context

// Fastly predifned identifier list.
// we listed as possible as found in Fastly document site,
// but perhapse there are more builtin identifiers.
func builtinIdentifiers() map[string]struct{} {
	return map[string]struct{}{
		// use for backend.ssl_check_cert
		// https://developer.fastly.com/reference/vcl/declarations/backend/
		"always": {},

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

		// use for digest.rsa_verify function hash_method argument
		// https://developer.fastly.com/reference/vcl/functions/cryptographic/digest-rsa-verify/
		"default": {},
		"sha256":  {},
		"sha384":  {},
		"sha512":  {},

		// use for digest.rsa_verify function base64_method argument
		// https://developer.fastly.com/reference/vcl/functions/cryptographic/digest-rsa-verify/
		"standard":  {},
		"url":       {},
		"url_nopad": {},
	}
}
