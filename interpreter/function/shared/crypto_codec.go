package shared

import (
	"bytes"
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

// Ident values constants
const (
	NOPAD = "nopad"
	CBC   = "cbc"
	CTR   = "ctr"
	PKCS7 = "pkcs7"
)

// CryptoCodec is common cryptographic for Fastly builtin function
type CryptoCodec struct {
	// builtin function name
	name string

	// constrant values
	cipher  string // "aes128" or "aes192" or "aes256"
	mode    string // "cbc" or "ctr"
	padding string // "pkcs7"  or "nopad"

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
	if mode != CBC && mode != CTR {
		return nil, errors.New(name, `Invalid mode. Valid mode ident is "cbc" or "ctr"`)
	}
	if padding != PKCS7 && padding != NOPAD {
		return nil, errors.New(name, `Invalid padding. Valid padding ident is "pkcs7" or "nopad"`)
	} else if mode == CTR && padding != NOPAD {
		return nil, errors.New(name, `When mode is ctr, padding must be "nopad"`)
	}

	return &CryptoCodec{
		cipher:  cipherId,
		mode:    mode,
		padding: padding,
		size:    size,
		name:    name,
	}, nil
}

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

func (c *CryptoCodec) Encrypt(hexKey, hexIv string, text []byte) ([]byte, error) {
	block, iv, err := c.decodeHex(hexKey, hexIv)
	if err != nil {
		return nil, err
	}

	if c.mode == CBC {
		return c.encryptCBC(block, iv, text), nil
	}
	return c.encryptCTR(block, iv, text), nil
}

func (c *CryptoCodec) encryptCBC(block cipher.Block, iv, text []byte) []byte {
	enc := cipher.NewCBCEncrypter(block, iv)

	padded := text
	if c.padding != NOPAD {
		padSize := aes.BlockSize - (len(text) & aes.BlockSize)
		padding := bytes.Repeat([]byte{byte(padSize)}, padSize)
		padded = append(padded, padding...)
	}

	encrypted := make([]byte, len(padded))
	enc.CryptBlocks(encrypted, padded)
	return encrypted
}

func (c *CryptoCodec) encryptCTR(block cipher.Block, iv, text []byte) []byte {
	stream := cipher.NewCTR(block, iv)
	encrypted := make([]byte, len(text))
	stream.XORKeyStream(encrypted, text)
	return encrypted
}

func (c *CryptoCodec) Decrypt(hexKey, hexIv string, text []byte) ([]byte, error) {
	block, iv, err := c.decodeHex(hexKey, hexIv)
	if err != nil {
		return nil, err
	}

	if c.mode == CBC {
		return c.decryptCBC(block, iv, text), nil
	}
	return c.decryptCTR(block, iv, text), nil
}

func (c *CryptoCodec) decryptCBC(block cipher.Block, iv, text []byte) []byte {
	dec := cipher.NewCBCDecrypter(block, iv)

	decrypted := make([]byte, len(text))
	dec.CryptBlocks(decrypted, text)

	if c.padding != NOPAD {
		// unpadding
		padSize := int(decrypted[len(decrypted)-1])
		decrypted = decrypted[:len(decrypted)-padSize]
	}
	return decrypted
}

func (c *CryptoCodec) decryptCTR(block cipher.Block, iv, text []byte) []byte {
	stream := cipher.NewCTR(block, iv)
	decrypted := make([]byte, len(text))
	stream.XORKeyStream(decrypted, text)
	return decrypted
}
