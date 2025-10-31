package shared

import (
	"crypto/cipher"

	"github.com/ysugimoto/falco/interpreter/function/errors"
)

// GCM mode encryption implementation
func (c *CryptoCodec) encryptGCM(block cipher.Block, nonce, payload []byte) ([]byte, error) {
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New(c.name, "Failed to create GCM cipher: %s", err)
	}

	// Seal encrypts and authenticates payload, appends the result to dst (nil here)
	// and appends the tag. Returns: ciphertext || tag
	ciphertext := aead.Seal(nil, nonce, payload, nil)
	return ciphertext, nil
}

// GCM mode decryption implementation
func (c *CryptoCodec) decryptGCM(block cipher.Block, nonce, payload []byte) ([]byte, error) {
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New(c.name, "Failed to create GCM cipher: %s", err)
	}

	// Open verifies the tag and decrypts ciphertext
	// If authentication fails, returns an error
	plaintext, err := aead.Open(nil, nonce, payload, nil)
	if err != nil {
		// Tag verification failed or ciphertext is malformed
		return nil, &BadDecryptError{
			Message: "GCM authentication tag verification failed",
		}
	}
	return plaintext, nil
}
