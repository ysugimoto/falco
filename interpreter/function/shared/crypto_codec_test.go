package shared

import (
	"encoding/hex"
	"testing"
)

func TestCryptoCodecCBC(t *testing.T) {
	plaintext := "6bc1bee22e409f96e93d7e117393172a"
	buf, _ := hex.DecodeString(plaintext)

	codec, err := NewCryptoCodec(
		"testing.function", "aes256", "cbc", "nopad",
	)
	if err != nil {
		t.Errorf("Unexpected codec initialization error: %s", err)
	}
	encrypted, err := codec.Encrypt(
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"000102030405060708090a0b0c0d0e0f",
		buf,
	)
	if err != nil {
		t.Errorf("Unexpected encrypt error: %s", err)
	}

	dec, err := codec.Decrypt(
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"000102030405060708090a0b0c0d0e0f",
		encrypted,
	)
	if err != nil {
		t.Errorf("Unexpected encrypt error: %s", err)
	}

	if hex.EncodeToString(dec) != plaintext {
		t.Errorf("encrypt/descript result unmatch, expeted=%s, got=%s", plaintext, hex.EncodeToString(dec))
	}
}

func TestCryptoCodecCTR(t *testing.T) {
	plaintext := "6bc1bee22e409f96e93d7e117393172a"
	buf, _ := hex.DecodeString(plaintext)

	codec, err := NewCryptoCodec(
		"testing.function", "aes256", "ctr", "nopad",
	)
	if err != nil {
		t.Errorf("Unexpected codec initialization error: %s", err)
	}
	encrypted, err := codec.Encrypt(
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"000102030405060708090a0b0c0d0e0f",
		buf,
	)
	if err != nil {
		t.Errorf("Unexpected encrypt error: %s", err)
	}

	dec, err := codec.Decrypt(
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"000102030405060708090a0b0c0d0e0f",
		encrypted,
	)
	if err != nil {
		t.Errorf("Unexpected encrypt error: %s", err)
	}

	if hex.EncodeToString(dec) != plaintext {
		t.Errorf("encrypt/descript result unmatch, expeted=%s, got=%s", plaintext, hex.EncodeToString(dec))
	}
}

func TestCryptoCodecGCM(t *testing.T) {
	plaintext := "6bc1bee22e409f96e93d7e117393172a"
	buf, _ := hex.DecodeString(plaintext)

	codec, err := NewCryptoCodec(
		"testing.function", "aes256", "gcm", "nopad",
	)
	if err != nil {
		t.Errorf("Unexpected codec initialization error: %s", err)
	}

	// GCM uses 12-byte nonce (24 hex chars)
	encrypted, err := codec.Encrypt(
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"000102030405060708090a0b",
		buf,
	)
	if err != nil {
		t.Errorf("Unexpected encrypt error: %s", err)
	}

	// Encrypted data should be plaintext + 16-byte tag
	if len(encrypted) != len(buf)+16 {
		t.Errorf("GCM encrypted length incorrect, expected=%d, got=%d", len(buf)+16, len(encrypted))
	}

	dec, err := codec.Decrypt(
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"000102030405060708090a0b",
		encrypted,
	)
	if err != nil {
		t.Errorf("Unexpected decrypt error: %s", err)
	}

	if hex.EncodeToString(dec) != plaintext {
		t.Errorf("encrypt/decrypt result unmatch, expected=%s, got=%s", plaintext, hex.EncodeToString(dec))
	}
}

func TestCryptoCodecCCM(t *testing.T) {
	plaintext := "6bc1bee22e409f96e93d7e117393172a"
	buf, _ := hex.DecodeString(plaintext)

	codec, err := NewCryptoCodec(
		"testing.function", "aes256", "ccm", "nopad",
	)
	if err != nil {
		t.Errorf("Unexpected codec initialization error: %s", err)
	}

	// CCM uses 7-byte nonce (14 hex chars)
	encrypted, err := codec.Encrypt(
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"00010203040506",
		buf,
	)
	if err != nil {
		t.Errorf("Unexpected encrypt error: %s", err)
	}

	// Encrypted data should be plaintext + 12-byte tag
	if len(encrypted) != len(buf)+12 {
		t.Errorf("CCM encrypted length incorrect, expected=%d, got=%d", len(buf)+12, len(encrypted))
	}

	dec, err := codec.Decrypt(
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"00010203040506",
		encrypted,
	)
	if err != nil {
		t.Errorf("Unexpected decrypt error: %s", err)
	}

	if hex.EncodeToString(dec) != plaintext {
		t.Errorf("encrypt/decrypt result unmatch, expected=%s, got=%s", plaintext, hex.EncodeToString(dec))
	}
}

func TestCryptoCodecCCMAuthenticationFailure(t *testing.T) {
	plaintext := "6bc1bee22e409f96e93d7e117393172a"
	buf, _ := hex.DecodeString(plaintext)

	codec, err := NewCryptoCodec(
		"testing.function", "aes128", "ccm", "nopad",
	)
	if err != nil {
		t.Errorf("Unexpected codec initialization error: %s", err)
	}

	encrypted, err := codec.Encrypt(
		"2b7e151628aed2a6abf7158809cf4f3c",
		"00010203040506",
		buf,
	)
	if err != nil {
		t.Errorf("Unexpected encrypt error: %s", err)
	}

	// Tamper with the ciphertext
	encrypted[0] ^= 0xFF

	// Decryption should fail due to authentication tag mismatch
	_, err = codec.Decrypt(
		"2b7e151628aed2a6abf7158809cf4f3c",
		"00010203040506",
		encrypted,
	)
	if err == nil {
		t.Errorf("Expected authentication error but got none")
	}

	// Should be a BadDecryptError
	if _, ok := err.(*BadDecryptError); !ok {
		t.Errorf("Expected BadDecryptError but got: %T", err)
	}
}

func TestCryptoCodecCCMInvalidIVLength(t *testing.T) {
	codec, err := NewCryptoCodec(
		"testing.function", "aes128", "ccm", "nopad",
	)
	if err != nil {
		t.Errorf("Unexpected codec initialization error: %s", err)
	}

	plaintext := "6bc1bee22e409f96e93d7e117393172a"
	buf, _ := hex.DecodeString(plaintext)

	// Try with wrong IV length (should be 14 hex chars = 7 bytes, not 24)
	_, err = codec.Encrypt(
		"2b7e151628aed2a6abf7158809cf4f3c",
		"000102030405060708090a0b", // 12 bytes, wrong for CCM
		buf,
	)
	if err == nil {
		t.Errorf("Expected IV length error but got none")
	}
}
