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
