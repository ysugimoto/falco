package shared

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

// CBC mode encryption implementation
func (c *CryptoCodec) encryptCBC(block cipher.Block, iv, payload []byte) []byte {
	enc := cipher.NewCBCEncrypter(block, iv)

	padded := payload
	if c.padding != NOPAD {
		padSize := aes.BlockSize - (len(payload) & aes.BlockSize)
		padding := bytes.Repeat([]byte{byte(padSize)}, padSize)
		padded = append(padded, padding...)
	}

	encrypted := make([]byte, len(padded))
	enc.CryptBlocks(encrypted, padded)
	return encrypted
}

// CBC mode decryption implementation
func (c *CryptoCodec) decryptCBC(block cipher.Block, iv, payload []byte) []byte {
	dec := cipher.NewCBCDecrypter(block, iv)

	decrypted := make([]byte, len(payload))
	dec.CryptBlocks(decrypted, payload)

	if c.padding != NOPAD {
		// unpadding
		padSize := int(decrypted[len(decrypted)-1])
		decrypted = decrypted[:len(decrypted)-padSize]
	}
	return decrypted
}
