package shared

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"

	"github.com/ysugimoto/falco/interpreter/function/errors"
)

const (
	ccmTagLength = 8
	ccmBlockSize = 16
)

// CCM mode encryption implementation according to https://datatracker.ietf.org/doc/html/rfc3610
func (c *CryptoCodec) encryptCCM(block cipher.Block, nonce, payload, aad []byte) ([]byte, error) {
	// nonce length must be between 7 and 13 octet
	if len(nonce) < 7 || len(nonce) > 13 {
		return nil, errors.New(c.name, "nonce must be between 7 and 13 octet")
	}
	// length field size must be between 2 and 8 octet
	L := 15 - len(nonce)
	if L < 2 || L > 8 {
		return nil, errors.New(c.name, "invalid L field computed, L must be between 2 and 8 octet")
	}

	// Compute authentication field (T)
	blocks := make([][]byte, 0)
	blocks = append(blocks, ccmBuildFirstBlock(nonce, L, len(payload), len(aad)))

	// If additional data is provided, encode first.
	// Note that Fastly won't accept additional authenticated data (a)
	if len(aad) > 0 {
		blocks = append(blocks, ccmEncodeAdditionalData(aad)...)
	}
	blocks = append(blocks, ccmSplitPayload(payload)...)

	// Compute CBC-MAC
	X := make([]byte, block.BlockSize())
	for _, B := range blocks {
		T := ccmComputeXOR(block, X, B)
		block.Encrypt(X, T)
	}
	// T is first M octets of mac
	T := X[:ccmTagLength]

	// Encrypt payload with CTR mode. we could use Go standard CTR encryption
	// but need to calculate S0 block manually.
	c0 := ccmCounterBlock(nonce, L, 0)
	s0 := make([]byte, block.BlockSize())
	block.Encrypt(s0, c0)

	// Important: turn on the last byte to 1 to be sure the CTR counter is 1
	c0[len(c0)-1] |= 1

	// Calculate authentication tag
	tag := make([]byte, ccmTagLength)
	for i := range ccmTagLength {
		tag[i] = T[i] ^ s0[i]
	}

	// Encrypt payload with CTR mode.
	stream := cipher.NewCTR(block, c0)
	ciphertext := make([]byte, len(payload))
	stream.XORKeyStream(ciphertext, payload)

	// Construct result that concats aad (if exists), cipher text and authentication tag
	var out []byte
	if len(aad) > 0 {
		out = append(out, aad...)
	}
	out = append(out, ciphertext...)
	out = append(out, tag...)

	return out, nil
}

// CCM mode decryption implementation according to https://datatracker.ietf.org/doc/html/rfc3610
func (c *CryptoCodec) decryptCCM(block cipher.Block, nonce, ciphertext, aad []byte) ([]byte, error) {
	// nonce length must be between 7 and 13 octet
	if len(nonce) < 7 || len(nonce) > 13 {
		return nil, errors.New(c.name, "nonce must be between 7 and 13 octet")
	}
	// length field size must be between 2 and 8 octet
	L := 15 - len(nonce)
	if L < 2 || L > 8 {
		return nil, errors.New(c.name, "invalid L field computed, L must be between 2 and 8 octet")
	}

	// Split aad, payload, and tag(masked)
	var payload, tag []byte
	if len(aad) > 0 {
		payload = ciphertext[len(aad) : len(ciphertext)-ccmTagLength]
		tag = ciphertext[len(ciphertext)-ccmTagLength:]
	} else {
		payload = ciphertext[:len(ciphertext)-ccmTagLength]
		tag = ciphertext[len(ciphertext)-ccmTagLength:]
	}

	// Recover T by unmasking
	c0 := ccmCounterBlock(nonce, L, 0)
	s0 := make([]byte, block.BlockSize())
	block.Encrypt(s0, c0)
	T := make([]byte, ccmTagLength)
	for i := range ccmTagLength {
		T[i] = tag[i] ^ s0[i]
	}

	c0[len(c0)-1] |= 1
	stream := cipher.NewCTR(block, c0)
	plaintext := make([]byte, len(payload))
	stream.XORKeyStream(plaintext, payload)

	// Compute CBC-MAC for the plaintext
	blocks := make([][]byte, 0)
	blocks = append(blocks, ccmBuildFirstBlock(nonce, L, len(plaintext), len(aad)))

	if len(aad) > 0 {
		blocks = append(blocks, ccmEncodeAdditionalData(aad)...)
	}
	blocks = append(blocks, ccmSplitPayload(plaintext)...)

	expectedT := make([]byte, block.BlockSize())
	for _, B := range blocks {
		t := ccmComputeXOR(block, expectedT, B)
		block.Encrypt(expectedT, t)
	}

	// Compare T and expectedT
	// Note that the expectedT has length of cipher block size - 16 bytes -so use first [ccmTagLength] bytes to compare
	if subtle.ConstantTimeCompare(expectedT[:ccmTagLength], T) != 1 {
		// Guard memory leak if failed
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, &BadDecryptError{
			Message: "CCM Decryption Error",
		}
	}
	return plaintext, nil
}

// Encode Additional Data (AAD)
func ccmEncodeAdditionalData(aad []byte) [][]byte {
	var encoded []byte

	if len(aad) < 0xFEFF {
		// If aad data length is less than equal 0xFEFF(65280), use 2 octets
		encoded = make([]byte, 2)
		binary.BigEndian.PutUint16(encoded, uint16(len(aad)))
	} else {
		// Otherwise, put 0xFFFE and use 4 octets
		encoded = make([]byte, 6)
		encoded[0] = 0xFF
		encoded[1] = 0xFE
		binary.BigEndian.PutUint32(encoded[2:], uint32(len(aad)))
	}
	encoded = append(encoded, aad...)
	return ccmSplitPayload(encoded)
}

// Build counter block
func ccmCounterBlock(nonce []byte, L, ctr int) []byte { // nolint: gocritic
	flags := byte((L - 1) & 0x7)
	buf := []byte{flags}
	buf = append(buf, nonce...)
	cb := make([]byte, L)

	for i := L - 1; i >= 0; i-- {
		cb[i] = byte(ctr & 0xFF)
		ctr >>= 8
	}
	buf = append(buf, cb...)
	return buf
}

// Compute XOR bytes for preparing CBC-MAC
func ccmComputeXOR(block cipher.Block, X, B []byte) []byte { // nolint: gocritic
	ms := min(block.BlockSize(), len(B))
	T := make([]byte, ms)
	for i := range ms {
		T[i] = X[i] ^ B[i]
	}
	return T
}

// Build first block as the following spec:
// |     1 byte      |
// |-----------------|
// | 7 6 5 4 3 2 1 0 |
// | 0 A M M M L L L |
//
// 7th bit is always zero (reserved)
// 6th bit indicates additional data (AAD) exists or not
// 3-5 bits holds the M'
// 0-2 bits holds the L'
func ccmBuildFirstBlock(nonce []byte, L, messageSize, aadSize int) []byte { // nolint: gocritic
	var flags byte

	// Turn on the 6th bit if AAD presents
	if aadSize > 0 {
		flags |= 1 << 6
	}
	flags |= ((ccmTagLength - 2) / 2) << 3 // set 3 to 5 bits
	flags |= byte(L - 1)                   // set 0 to 2 bits
	block := make([]byte, ccmBlockSize)
	block[0] = flags
	binary.BigEndian.PutUint64(block[8:], uint64(messageSize))
	copy(block[1:16-L], nonce)

	return block
}

// Split payload into 16 byte blocks.
// Fastly documentation says function must be called with `nopad` identifier when encrypt with CCM mode.
func ccmSplitPayload(payload []byte) [][]byte {
	size := len(payload)
	if size == 0 {
		return [][]byte{}
	}

	blocks := make([][]byte, 0)
	for i := 0; i < size; i += ccmBlockSize {
		end := min(i+ccmBlockSize, size)
		block := make([]byte, ccmBlockSize)
		copy(block, payload[i:end])
		blocks = append(blocks, block)
	}
	return blocks
}
