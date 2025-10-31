package shared

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"

	"github.com/ysugimoto/falco/interpreter/function/errors"
)

var BlockSizeMap = map[string]int{
	"aes128": 16,
	"aes192": 24,
	"aes256": 32,
}

// BadDecryptError is returned when GCM tag verification fails
type BadDecryptError struct {
	Message string
}

func (e *BadDecryptError) Error() string {
	return e.Message
}

// Ident values constants
const (
	NOPAD = "nopad"
	CBC   = "cbc"
	CTR   = "ctr"
	GCM   = "gcm"
	CCM   = "ccm"
	PKCS7 = "pkcs7"
)

// CryptoCodec is common cryptographic for Fastly builtin function
type CryptoCodec struct {
	// builtin function name
	name string

	// constrant values
	cipher  string // "aes128" or "aes192" or "aes256"
	mode    string // "cbc", "ctr", or "gcm"
	padding string // "pkcs7" or "nopad"

	// block size
	size int
}

func NewCryptoCodec(
	name string,
	cipherId, mode, padding string,
) (*CryptoCodec, error) {

	size, ok := BlockSizeMap[cipherId]
	if !ok {
		return nil, errors.New(name, `Invalid cipher. Valid cipher ident is "aes128", "aes192" or "aes256"`)
	}
	if mode != CBC && mode != CTR && mode != GCM && mode != CCM {
		return nil, errors.New(name, `Invalid mode. Valid mode ident is "cbc", "ctr", "gcm" or "ccm"`)
	}
	if padding != PKCS7 && padding != NOPAD {
		return nil, errors.New(name, `Invalid padding. Valid padding ident is "pkcs7" or "nopad"`)
	} else if (mode == CTR || mode == GCM || mode == CCM) && padding != NOPAD {
		return nil, errors.New(name, `When mode is ctr, gcm, or ccm, padding must be "nopad"`)
	}

	return &CryptoCodec{
		cipher:  cipherId,
		mode:    mode,
		padding: padding,
		size:    size,
		name:    name,
	}, nil
}

// Utitiliy method decode hex to bin
func (c *CryptoCodec) decodeHex(hexKey, hexIv string) (cipher.Block, []byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, nil, errors.New(c.name, "Failed to decode key hex string")
	} else if len(key) != c.size {
		return nil, nil, errors.New(
			c.name,
			"Invalid key size. %s cipher requires %d size key but got %d",
			c.cipher, c.size, len(key),
		)
	}

	iv, err := hex.DecodeString(hexIv)
	if err != nil {
		return nil, nil, errors.New(c.name, "Failed to decode iv hex string")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, errors.New(c.name, "Failed to create AES cipher block: %s", err)
	}

	return block, iv, nil
}

// Public method, encryption
func (c *CryptoCodec) Encrypt(hexKey, hexIv string, text []byte) ([]byte, error) {
	block, iv, err := c.decodeHex(hexKey, hexIv)
	if err != nil {
		return nil, err
	}

	switch c.mode {
	case CBC:
		return c.encryptCBC(block, iv, text), nil
	case CTR:
		return c.encryptCTR(block, iv, text), nil
	case GCM:
		return c.encryptGCM(block, iv, text)
	case CCM:
		return c.encryptCCM(block, iv, text, nil)
	}
	return nil, errors.New(c.name, "Unsupported mode: %s", c.mode)
}

// Public method, decryption
func (c *CryptoCodec) Decrypt(hexKey, hexIv string, text []byte) ([]byte, error) {
	block, iv, err := c.decodeHex(hexKey, hexIv)
	if err != nil {
		return nil, err
	}

	switch c.mode {
	case CBC:
		return c.decryptCBC(block, iv, text), nil
	case CTR:
		return c.decryptCTR(block, iv, text), nil
	case GCM:
		return c.decryptGCM(block, iv, text)
	case CCM:
		return c.decryptCCM(block, iv, text, nil)
	}
	return nil, errors.New(c.name, "Unsupported mode: %s", c.mode)
}
