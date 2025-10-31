package shared

import "crypto/cipher"

// CTR mode ecnryption implementation
func (c *CryptoCodec) encryptCTR(block cipher.Block, iv, payload []byte) []byte {
	stream := cipher.NewCTR(block, iv)
	encrypted := make([]byte, len(payload))
	stream.XORKeyStream(encrypted, payload)
	return encrypted
}

// CTR mode decryption implementation
func (c *CryptoCodec) decryptCTR(block cipher.Block, iv, payload []byte) []byte {
	stream := cipher.NewCTR(block, iv)
	decrypted := make([]byte, len(payload))
	stream.XORKeyStream(decrypted, payload)
	return decrypted
}
