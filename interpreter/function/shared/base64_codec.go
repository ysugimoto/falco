package shared

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"strings"
)

var nullByte = []byte{0}

// Stop and return the point of Null-Byte found
func terminateNullByte(decoded []byte) []byte {
	before, _, _ := bytes.Cut(decoded, nullByte)
	return before
}

// Even stopping decoding, we need to padding sign to success golang base64 decoding
func padding(b []byte) []byte {
	for len(b)%4 > 0 {
		b = append(b, 0x3D)
	}
	return b
}

// Remove invalid characters for standard encoding
func removeInvalidCharactersStd(src string) string {
	removed := new(bytes.Buffer)
	reader := bufio.NewReader(strings.NewReader(src))

	for {
		b, err := reader.ReadByte()
		if err == io.EOF {
			break
		}
		switch {
		case b >= 0x41 && b <= 0x5A: // A-Z
			removed.WriteByte(b)
		case b >= 0x61 && b <= 0x7A: // a-z
			removed.WriteByte(b)
		case b >= 0x30 && b <= 0x39: // 0-9
			removed.WriteByte(b)
		case b == 0x2B || b == 0x2F: // + or /
			removed.WriteByte(b)
		case b == 0x3D: // =
			// If "=" sign found, next byte must also be "="
			if peek, err := reader.Peek(1); err != nil && peek[0] == 0x3D {
				removed.WriteByte(b)
				removed.WriteByte(b)
				// skip next "=" character
				reader.ReadByte() // nolint:errcheck
				continue
			}
			// Otherwise, treat as invalid character, stop decoding
			return string(padding(removed.Bytes()))
		default:
			// Invalid characters, skip it
		}
	}

	return string(padding(removed.Bytes()))
}

// Remove invalid characters for base64-url encoding
func removeInvalidCharactersUrl(src string) string {
	removed := new(bytes.Buffer)
	r := bufio.NewReader(strings.NewReader(src))

	for {
		b, err := r.ReadByte()
		if err == io.EOF {
			break
		}
		switch {
		case b >= 0x41 && b <= 0x5A: // A-Z
			removed.WriteByte(b)
		case b >= 0x61 && b <= 0x7A: // a-z
			removed.WriteByte(b)
		case b >= 0x30 && b <= 0x39: // 0-9
			removed.WriteByte(b)
		case b == 0x2B: // + should replace to -
			removed.WriteByte(0x2D)
		case b == 0x2F: // / should replace to _
			removed.WriteByte(0x5F)
		case b == 0x2D || b == 0x5F: // + or /
			removed.WriteByte(b)
		case b == 0x3D: // =
			// If "=" sign found, next byte must also be "="
			if peek, err := r.Peek(1); err != nil && peek[0] == 0x3D {
				removed.WriteByte(b)
				removed.WriteByte(b)
				// skip next "=" character
				r.ReadByte() // nolint:errcheck
				continue
			}
			// Otherwise, treat as invalid character, stop decoding
			return string(padding(removed.Bytes()))
		default:
			// Invalid characters, skip it
		}
	}

	return string(padding(removed.Bytes()))
}

// Remove invalid characters for base64-url nopadding encoding
func removeInvalidCharactersUrlNoPad(src string) string {
	removed := new(bytes.Buffer)
	r := bufio.NewReader(strings.NewReader(src))

	for {
		b, err := r.ReadByte()
		if err == io.EOF {
			break
		}
		switch {
		case b >= 0x41 && b <= 0x5A: // A-Z
			removed.WriteByte(b)
		case b >= 0x61 && b <= 0x7A: // a-z
			removed.WriteByte(b)
		case b >= 0x30 && b <= 0x39: // 0-9
			removed.WriteByte(b)
		case b == 0x2B: // + should replace to -
			removed.WriteByte(0x2D)
		case b == 0x2F: // / should replace to _
			removed.WriteByte(0x5F)
		case b == 0x2D || b == 0x5F: // + or /
			removed.WriteByte(b)
		default:
			// Note: the "=" sign also treats as invalid character
			// Invalid characters, skip it
		}
	}

	return removed.String()
}

// Standard base64 encoding
func Base64Encode(src string) string {
	return base64.StdEncoding.EncodeToString([]byte(src))
}

// base64-url encoding
func Base64UrlEncode(src string) string {
	return base64.URLEncoding.EncodeToString([]byte(src))
}

// base64-url nopadding encoding
func Base64UrlEncodeNoPad(src string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(src))
}

// Standard base64 decoding
func Base64Decode(src string) string {
	removed := removeInvalidCharactersStd(src)
	dec, _ := base64.StdEncoding.DecodeString(removed) // nolint:errcheck
	return string(terminateNullByte(dec))
}

// base64-url decoding
func Base64UrlDecode(src string) string {
	removed := removeInvalidCharactersUrl(src)
	dec, _ := base64.URLEncoding.DecodeString(removed) // nolint:errcheck
	return string(terminateNullByte(dec))
}

// base64-url nopadding decoding
func Base64UrlDecodeNoPad(src string) string {
	removed := removeInvalidCharactersUrlNoPad(src)
	dec, _ := base64.RawURLEncoding.DecodeString(removed) // nolint:errcheck
	return string(terminateNullByte(dec))
}
