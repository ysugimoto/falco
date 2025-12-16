package shared

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/pkg/errors"
)

var ErrInvalidMultiByteSequence = errors.New("Invalid multi-byte sequence")

// Percent Encoding is described at [RFC3986](https://datatracker.ietf.org/doc/html/rfc3986#section-2.4)
// But Fastly's urlencode / urldecode function seems to be a pretty different.
// Therefore we don't use golang's net/url package to encode and decode,
// implement our own logic that is almost checked by actual Fastly behavior on the fiddle.
// ref https://fiddle.fastly.dev/fiddle/bf3e21e5

// Check byte is unreserved byte
func isUnreservedByte(b byte) bool {
	// Ascii bytes, "-", ".", "_", "~"
	return isHexBytes(b) || b == 0x2D || b == 0x2E || b == 0x5F || b == 0x7E
}

// Check byte is [a-zA-Z0-9]
func isHexBytes(b byte) bool {
	return (0x41 <= b && b <= 0x5A) || (0x61 <= b && b <= 0x7A) || (0x30 <= b && b <= 0x39)
}

// Percent encoding function for urlencode() builtin function
func UrlEncode(src string) (string, error) {
	reader := bufio.NewReader(strings.NewReader(src))
	var encoded []byte

	for {
		// Source string may contain multi-byte string so we encode using rune
		b, s, err := reader.ReadRune()
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", errors.WithStack(err)
		}

		// If size is greater then 1, it indicates the rune is multi-byte.
		if s > 1 {
			sb := make([]byte, s)
			if n := utf8.EncodeRune(sb, b); n != s {
				return "", errors.WithStack(errors.New("Failed to encode bytes to rune"))
			}
			for _, v := range sb {
				encoded = append(encoded, fmt.Sprintf("%%%02X", v)...)
			}
			continue
		}

		switch {
		case b == 0x25: // "%"
			// When percent sign found, encode following 2 bytes as following format
			// % HEXDIG HEXDIG
			// But following byte may not be HEXDIG (e.g %&), then encode as %25
			hex, err := reader.Peek(2)
			if err != nil {
				return "", errors.WithStack(err)
			}

			// Check 2 bytes are HEXDIG
			if !isHexBytes(hex[0]) || !isHexBytes(hex[1]) {
				encoded = append(encoded, fmt.Sprintf("%%%02X", b)...)
				continue
			}

			// Decode 2 bytes to byte integer
			n, err := strconv.ParseInt(string(hex), 16, 64)
			if err != nil {
				return "", errors.WithStack(err)
			}
			// If decoded byte is out of range of ascii code, stop encoding
			if 0x01 > n || 0x7F < n {
				goto OUT
			}
			encoded = append(encoded, byte(b))
			encoded = append(encoded, hex...)
			// forward 2 bytes
			reader.Read(make([]byte, 2)) // nolint:errcheck
		case isUnreservedByte(byte(b)):
			// Unreserved byte does not need to percent encode, add raw byte
			encoded = append(encoded, byte(b))
		default:
			// Percent encoding
			encoded = append(encoded, fmt.Sprintf("%%%02X", b)...)
		}
	}
OUT:

	return string(encoded), nil
}

// Percent decoding function for urldecode() builtin function
func UrlDecode(src string) (string, error) {
	reader := bufio.NewReader(strings.NewReader(src))
	var decoded []byte

	for {
		// encoded string always only has bytes
		b, err := reader.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", errors.WithStack(err)
		}

		if b == 0x25 { // "%"
			hex, err := reader.Peek(2)
			if err != nil {
				return "", errors.WithStack(err)
			}

			// Check 2 bytes are HEXDIG
			if !isHexBytes(hex[0]) || !isHexBytes(hex[1]) {
				decoded = append(decoded, b)
				continue
			}

			n, err := strconv.ParseInt(string(hex), 16, 64)
			if err != nil {
				return "", errors.WithStack(err)
			}

			switch {
			case n <= 0x00:
				// Stop decoding if byte is nullbyte
				goto OUT
			case n <= 0x7F:
				// If byte is within ascii code range, append raw bytes
				decoded = append(decoded, byte(n))
				// Forward 2 bytes
				reader.Read(make([]byte, 2)) // nolint:errcheck
			default:
				// If byte is out of range of ascii code, decode as multi-byte string
				reader.Read(make([]byte, 2)) // nolint:errcheck

				multiBytes, err := decodeMultiBytes(reader, byte(n))
				if err != nil {
					return "", errors.WithStack(err)
				}

				decoded = append(decoded, multiBytes...)
			}
		} else {
			decoded = append(decoded, byte(b))
		}
	}
OUT:

	return string(decoded), nil
}

func decodeMultiBytes(reader *bufio.Reader, firstByte byte) ([]byte, error) {
	mbs := []byte{firstByte}

	for range utf8.UTFMax {
		sb := make([]byte, 3) // create 3 bytes for %HH
		if _, err := reader.Read(sb); err != nil {
			return nil, errors.WithStack(err)
		}
		// First byte must be '%'
		if sb[0] != 0x25 {
			return nil, errors.WithStack(ErrInvalidMultiByteSequence)
		}
		sb = sb[1:]
		if !isHexBytes(sb[0]) || !isHexBytes(sb[1]) {
			return nil, errors.WithStack(ErrInvalidMultiByteSequence)
		}

		n, err := strconv.ParseInt(string(sb), 16, 64)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		mbs = append(mbs, byte(n))
		// Try to decode as rune. If succeeded, break loop
		if r, _ := utf8.DecodeRune(mbs); r != utf8.RuneError {
			return mbs, nil
		}
	}

	// If bytes did not return inside for-loop, raise an error of invalid multi-byte sequence
	return nil, errors.WithStack(ErrInvalidMultiByteSequence)
}
