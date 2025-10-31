package shared

import (
	"bytes"
	"crypto/aes"
	cp "crypto/cipher"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

type TestVector struct {
	aesKey    []byte
	nonce     []byte
	input     []byte
	aadOctets int
	cbcIvIn   []byte
	cbcIvOut  []byte
	processes []struct {
		xor []byte
		aes []byte
	}
	cbcMac   []byte
	ctrStart []byte
	ctrs     [][]byte
	ctrMac   []byte
	result   []byte
}

var testVectors = []TestVector{
	// Test Vector #1
	{
		aesKey: []byte{
			0xC0, 0xC1, 0xC2, 0xC3,
			0xC4, 0xC5, 0xC6, 0xC7,
			0xC8, 0xC9, 0xCA, 0xCB,
			0xCC, 0xCD, 0xCE, 0xCF,
		},
		nonce: []byte{
			0x00, 0x00, 0x00, 0x03,
			0x02, 0x01, 0x00, 0xA0,
			0xA1, 0xA2, 0xA3, 0xA4,
			0xA5,
		},
		input: []byte{
			0x00, 0x01, 0x02, 0x03,
			0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F,
			0x10, 0x11, 0x12, 0x13,
			0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1A, 0x1B,
			0x1C, 0x1D, 0x1E,
		},
		aadOctets: 8,
		cbcIvIn: []byte{
			0x59, 0x00, 0x00, 0x00,
			0x03, 0x02, 0x01, 0x00,
			0xA0, 0xA1, 0xA2, 0xA3,
			0xA4, 0xA5, 0x00, 0x17,
		},
		cbcIvOut: []byte{
			0xEB, 0x9D, 0x55, 0x47,
			0x73, 0x09, 0x55, 0xAB,
			0x23, 0x1E, 0x0A, 0x2D,
			0xFE, 0x4B, 0x90, 0xD6,
		},
		processes: []struct {
			xor []byte
			aes []byte
		}{
			{
				xor: []byte{
					0xEB, 0x95, 0x55, 0x46,
					0x71, 0x0A, 0x51, 0xAE,
					0x25, 0x19, 0x0A, 0x2D,
					0xFE, 0x4B, 0x90, 0xD6,
				}, // [hdr]
				aes: []byte{
					0xCD, 0xB6, 0x41, 0x1E,
					0x3C, 0xDC, 0x9B, 0x4F,
					0x5D, 0x92, 0x58, 0xB6,
					0x9E, 0xE7, 0xF0, 0x91,
				},
			},
			{
				xor: []byte{
					0xC5, 0xBF, 0x4B, 0x15,
					0x30, 0xD1, 0x95, 0x40,
					0x4D, 0x83, 0x4A, 0xA5,
					0x8A, 0xF2, 0xE6, 0x86,
				}, // [msg]
				aes: []byte{
					0x9C, 0x38, 0x40, 0x5E,
					0xA0, 0x3C, 0x1B, 0xC9,
					0x04, 0xB5, 0x8B, 0x40,
					0xC7, 0x6C, 0xA2, 0xEB,
				},
			},
			{
				xor: []byte{
					0x84, 0x21, 0x5A, 0x45,
					0xBC, 0x21, 0x05, 0xC9,
					0x04, 0xB5, 0x8B, 0x40,
					0xC7, 0x6C, 0xA2, 0xEB,
				}, // [msg]
				aes: []byte{
					0x2D, 0xC6, 0x97, 0xE4,
					0x11, 0xCA, 0x83, 0xA8,
					0x60, 0xC2, 0xC4, 0x06,
					0xCC, 0xAA, 0x54, 0x2F,
				},
			},
		},
		cbcMac: []byte{
			0x2D, 0xC6, 0x97, 0xE4,
			0x11, 0xCA, 0x83, 0xA8,
		},
		ctrStart: []byte{
			0x01, 0x00, 0x00, 0x00,
			0x03, 0x02, 0x01, 0x00,
			0xA0, 0xA1, 0xA2, 0xA3,
			0xA4, 0xA5, 0x00, 0x01,
		},
		ctrs: [][]byte{
			{
				0x50, 0x85, 0x9D, 0x91,
				0x6D, 0xCB, 0x6D, 0xDD,
				0xE0, 0x77, 0xC2, 0xD1,
				0xD4, 0xEC, 0x9F, 0x97,
			},
			{
				0x75, 0x46, 0x71, 0x7A,
				0xC6, 0xDE, 0x9A, 0xFF,
				0x64, 0x0C, 0x9C, 0x06,
				0xDE, 0x6D, 0x0D, 0x8F,
			},
		},
		ctrMac: []byte{
			0x3A, 0x2E, 0x46, 0xC8,
			0xEC, 0x33, 0xA5, 0x48,
		},
		result: []byte{
			0x00, 0x01, 0x02, 0x03,
			0x04, 0x05, 0x06, 0x07,
			0x58, 0x8C, 0x97, 0x9A,
			0x61, 0xC6, 0x63, 0xD2,
			0xF0, 0x66, 0xD0, 0xC2,
			0xC0, 0xF9, 0x89, 0x80,
			0x6D, 0x5F, 0x6B, 0x61,
			0xDA, 0xC3, 0x84, 0x17,
			0xE8, 0xD1, 0x2C, 0xFD,
			0xF9, 0x26, 0xE0,
		},
	},
	// Test Vector #2
	{
		aesKey: []byte{
			0xC0, 0xC1, 0xC2, 0xC3,
			0xC4, 0xC5, 0xC6, 0xC7,
			0xC8, 0xC9, 0xCA, 0xCB,
			0xCC, 0xCD, 0xCE, 0xCF,
		},
		nonce: []byte{
			0x00, 0x00, 0x00, 0x04,
			0x03, 0x02, 0x01, 0xA0,
			0xA1, 0xA2, 0xA3, 0xA4,
			0xA5,
		},
		input: []byte{
			0x00, 0x01, 0x02, 0x03,
			0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F,
			0x10, 0x11, 0x12, 0x13,
			0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1A, 0x1B,
			0x1C, 0x1D, 0x1E, 0x1F,
		},
		aadOctets: 8,
		cbcIvIn: []byte{
			0x59, 0x00, 0x00, 0x00,
			0x04, 0x03, 0x02, 0x01,
			0xA0, 0xA1, 0xA2, 0xA3,
			0xA4, 0xA5, 0x00, 0x18,
		},
		cbcIvOut: []byte{
			0xF0, 0xC2, 0x54, 0xD3,
			0xCA, 0x03, 0xE2, 0x39,
			0x70, 0xBD, 0x24, 0xA8,
			0x4C, 0x39, 0x9E, 0x77,
		},
		processes: []struct {
			xor []byte
			aes []byte
		}{
			{
				xor: []byte{
					0xF0, 0xCA, 0x54, 0xD2,
					0xC8, 0x00, 0xE6, 0x3C,
					0x76, 0xBA, 0x24, 0xA8,
					0x4C, 0x39, 0x9E, 0x77,
				},
				aes: []byte{
					0x48, 0xDE, 0x8B, 0x86,
					0x28, 0xEA, 0x4A, 0x40,
					0x00, 0xAA, 0x42, 0xC2,
					0x95, 0xBF, 0x4A, 0x8C,
				},
			},
			{
				xor: []byte{
					0x40, 0xD7, 0x81, 0x8D,
					0x24, 0xE7, 0x44, 0x4F,
					0x10, 0xBB, 0x50, 0xD1,
					0x81, 0xAA, 0x5C, 0x9B,
				},
				aes: []byte{
					0x0F, 0x89, 0xFF, 0xBC,
					0xA6, 0x2B, 0xC2, 0x4F,
					0x13, 0x21, 0x5F, 0x16,
					0x87, 0x96, 0xAA, 0x33,
				},
			},
			{
				xor: []byte{
					0x17, 0x90, 0xE5, 0xA7,
					0xBA, 0x36, 0xDC, 0x50,
					0x13, 0x21, 0x5F, 0x16,
					0x87, 0x96, 0xAA, 0x33,
				},
				aes: []byte{
					0xF7, 0xB9, 0x05, 0x6A,
					0x86, 0x92, 0x6C, 0xF3,
					0xFB, 0x16, 0x3D, 0xC4,
					0x99, 0xEF, 0xAA, 0x11,
				},
			},
		},
		cbcMac: []byte{
			0xF7, 0xB9, 0x05, 0x6A,
			0x86, 0x92, 0x6C, 0xF3,
		},
		ctrStart: []byte{
			0x01, 0x00, 0x00, 0x00,
			0x04, 0x03, 0x02, 0x01,
			0xA0, 0xA1, 0xA2, 0xA3,
			0xA4, 0xA5, 0x00, 0x01,
		},
		ctrs: [][]byte{
			{
				0x7A, 0xC0, 0x10, 0x3D,
				0xED, 0x38, 0xF6, 0xC0,
				0x39, 0x0D, 0xBA, 0x87,
				0x1C, 0x49, 0x91, 0xF4,
			},
			{
				0xD4, 0x0C, 0xDE, 0x22,
				0xD5, 0xF9, 0x24, 0x24,
				0xF7, 0xBE, 0x9A, 0x56,
				0x9D, 0xA7, 0x9F, 0x51,
			},
		},
		ctrMac: []byte{
			0x57, 0x28, 0xD0, 0x04,
			0x96, 0xD2, 0x65, 0xE5,
		},
		result: []byte{
			0x00, 0x01, 0x02, 0x03,
			0x04, 0x05, 0x06, 0x07,
			0x72, 0xC9, 0x1A, 0x36,
			0xE1, 0x35, 0xF8, 0xCF,
			0x29, 0x1C, 0xA8, 0x94,
			0x08, 0x5C, 0x87, 0xE3,
			0xCC, 0x15, 0xC4, 0x39,
			0xC9, 0xE4, 0x3A, 0x3B,
			0xA0, 0x91, 0xD5, 0x6E,
			0x10, 0x40, 0x09, 0x16,
		},
	},
}

func printHex(b []byte) string {
	h := hex.EncodeToString(b)
	var ret []string
	for i := 0; i < len(h); i += 2 {
		ret = append(ret, h[i:i+2])
	}
	return strings.Join(ret, " ")
}

// CCM testing, check satisfies testing vector which is defined at:
// https://datatracker.ietf.org/doc/html/rfc3610#section-8
func TestCryptoCodecCCM(t *testing.T) {
	for i, v := range testVectors {
		if i > 0 {
			continue
		}
		name := fmt.Sprintf("CCM Test Vector #%d", i+1)
		t.Run(name, func(t *testing.T) {

			// Assert self-implemented logic for test vector
			ciphertext := assertCCMEncryption(t, v)
			if ciphertext == nil {
				return
			}
			assertCCMDecription(t, v, ciphertext)

			// And ensure our CCM Codec is correct
			cipher, err := aes.NewCipher(v.aesKey)
			if err != nil {
				t.Errorf("Failed to create cipher: %s", err)
			}

			var aad, payload []byte
			if v.aadOctets > 0 {
				aad = v.input[:v.aadOctets]
				payload = v.input[v.aadOctets:]
			} else {
				payload = v.input
			}
			codec, err := NewCryptoCodec("test", "aes256", CCM, NOPAD)
			if err != nil {
				t.Errorf("CryptCodec creation error: %s", err)
				return
			}
			ret, err := codec.encryptCCM(cipher, v.nonce, payload, aad)
			if err != nil {
				t.Errorf("CCM Encryption error: %s", err)
				return
			}
			if !bytes.Equal(ret, v.result) {
				t.Errorf("Encryption result mismatch \n%s\n%s", printHex(ret), printHex(v.result))
				return
			}
			dec, err := codec.decryptCCM(cipher, v.nonce, ret, aad)
			if err != nil {
				t.Errorf("CCM Decription error: %s", err)
				return
			}
			if !bytes.Equal(dec, payload) {
				t.Errorf("Decription result mismatch \n%s\n%s", printHex(dec), printHex(payload))
				return
			}
		})
	}
}

func assertCCMEncryption(t *testing.T, v TestVector) []byte {
	cipher, err := aes.NewCipher(v.aesKey)
	if err != nil {
		t.Errorf("Failed to create cipher: %s", err)
		return nil
	}

	var aad, payload []byte
	if v.aadOctets > 0 {
		aad = v.input[:v.aadOctets]
		payload = v.input[v.aadOctets:]
	} else {
		payload = v.input
	}

	L := 15 - len(v.nonce)
	b0 := ccmBuildFirstBlock(v.nonce, L, len(payload), len(aad))
	if !bytes.Equal(b0, v.cbcIvIn) {
		t.Errorf("First block mismatch\n%s\n%s", printHex(b0), printHex(v.cbcIvIn))
		return nil
	}

	blocks := make([][]byte, 0)
	blocks = append(blocks, b0)
	blocks = append(blocks, ccmEncodeAdditionalData(aad)...)
	for _, chunk := range ccmSplitPayload(payload) {
		blocks = append(blocks, chunk)
	}

	X := make([]byte, cipher.BlockSize())
	T := ccmComputeXOR(cipher, X, blocks[0])
	cipher.Encrypt(X, T)
	if !bytes.Equal(X, v.cbcIvOut) {
		t.Errorf("cbcIvOut mismatch\n%s\n%s", printHex(X), printHex(v.cbcIvOut))
		return nil
	}
	for i, proc := range v.processes {
		T := ccmComputeXOR(cipher, X, blocks[i+1])
		if !bytes.Equal(T, proc.xor) {
			t.Errorf("XOR result mismatch for index %d\n%s\n%s", i+1, printHex(T), printHex(proc.xor))
			return nil
		}
		cipher.Encrypt(X, T)
		if !bytes.Equal(X, proc.aes) {
			t.Errorf("AES result mismatch for index %d\n%s\n%s", i+1, printHex(T), printHex(proc.xor))
			return nil
		}
	}

	mac := X[:ccmTagLength]
	if !bytes.Equal(mac, v.cbcMac) {
		t.Errorf("MAC mismatch \n%s\n%s", printHex(mac), printHex(v.cbcMac))
		return nil
	}
	c0 := ccmCounterBlock(v.nonce, L, 0)
	s0 := make([]byte, cipher.BlockSize())
	cipher.Encrypt(s0, c0)
	c0[len(c0)-1] = 1
	if !bytes.Equal(c0, v.ctrStart) {
		t.Errorf("CTR Start mismatch \n%s\n%s", printHex(c0), printHex(v.ctrStart))
		return nil
	}

	tag := make([]byte, ccmTagLength)
	for i := range ccmTagLength {
		tag[i] = mac[i] ^ s0[i]
	}

	// Create copy of c0 to ensure the CTR encryption process (for testing)
	c := make([]byte, len(c0))
	copy(c, c0)

	S := make([]byte, cipher.BlockSize())
	for i := 1; i < len(v.ctrs); i++ {
		cipher.Encrypt(S, c)
		if !bytes.Equal(S, v.ctrs[i-1]) {
			t.Errorf("CTR[%04d] mismatch \n%s\n%s", i, printHex(S), printHex(v.ctrs[i-1]))
		}
		c = ccmCounterBlock(v.nonce, L, i+1)
	}

	stream := cp.NewCTR(cipher, c0)
	ciphertext := make([]byte, len(payload))
	stream.XORKeyStream(ciphertext, payload)

	out := make([]byte, len(aad)+len(ciphertext)+len(tag))
	copy(out[:len(aad)], aad)
	copy(out[len(aad):len(ciphertext)+len(aad)], ciphertext)
	copy(out[len(aad)+len(ciphertext):], tag)

	if !bytes.Equal(out, v.result) {
		t.Errorf("Encryption result mismatch \n%s\n%s", printHex(out), printHex(v.result))
		return nil
	}

	return out
}

func assertCCMDecription(t *testing.T, v TestVector, ciphertext []byte) {
	cipher, err := aes.NewCipher(v.aesKey)
	if err != nil {
		t.Errorf("Failed to create cipher: %s", err)
		return
	}

	var aad, payload, tag []byte
	if v.aadOctets > 0 {
		aad = ciphertext[:v.aadOctets]
		payload = ciphertext[v.aadOctets : len(ciphertext)-ccmTagLength]
		tag = ciphertext[len(ciphertext)-ccmTagLength:]
	} else {
		payload = ciphertext[:len(ciphertext)-ccmTagLength]
		tag = ciphertext[len(ciphertext)-ccmTagLength:]
	}

	L := 15 - len(v.nonce)

	// Recover T
	c0 := ccmCounterBlock(v.nonce, L, 0)
	s0 := make([]byte, cipher.BlockSize())
	cipher.Encrypt(s0, c0)
	T := make([]byte, ccmTagLength)
	for i := range ccmTagLength {
		T[i] = tag[i] ^ s0[i]
	}

	c0[len(c0)-1] |= 1
	stream := cp.NewCTR(cipher, c0)
	plaintext := make([]byte, len(payload))
	stream.XORKeyStream(plaintext, payload)

	// Compute CBC-MAC
	blocks := make([][]byte, 0)
	blocks = append(blocks, ccmBuildFirstBlock(v.nonce, L, len(plaintext), len(aad)))

	if len(aad) > 0 {
		blocks = append(blocks, ccmEncodeAdditionalData(aad)...)
	}
	blocks = append(blocks, ccmSplitPayload(plaintext)...)

	expectedT := make([]byte, cipher.BlockSize())
	for _, B := range blocks {
		t := ccmComputeXOR(cipher, expectedT, B)
		cipher.Encrypt(expectedT, t)
	}

	if subtle.ConstantTimeCompare(expectedT[:ccmTagLength], T) != 1 {
		t.Errorf("Decription mismatch: \n%s\n%s", printHex(expectedT[:ccmTagLength]), printHex(T))
		// Guard memory leak
		for i := range plaintext {
			plaintext[i] = 0
		}
		t.Errorf("CCM Decription Error")
		return
	}

	if !bytes.Equal(plaintext, v.input[v.aadOctets:]) {
		t.Errorf("Decrpyion result mismatch \n%s\n%s", printHex(plaintext), printHex(v.input))
		return
	}
}
