package parser

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/pkg/errors"
)

// Parse string escapes and return the resulting string with the decoded escaped
// values.
func decodeStringEscapes(s string) (string, error) {
	var parsed string
	r := bufio.NewReader(strings.NewReader(s))

	for {
		c, _, err := r.ReadRune()
		if err == io.EOF {
			break
		}
		if c == 0 {
			break
		}
		if c == '%' {
			var s string
			if peek(r) == 'u' {
				next(r)
				s, err = codePointEscape(r)
			} else {
				s, err = utf8Escape(r)
			}
			// stop processing string on a null byte.
			if err == NULLbyte {
				break
			} else if err != nil {
				return "", err
			}
			parsed += s
		} else {
			parsed += string(c)
		}
	}

	return parsed, nil
}

// isHex reports whether the rune is a hex digit.
func isHex(c rune) bool {
	return '0' <= c && c <= '9' || 'a' <= unicode.ToLower(c) && unicode.ToLower(c) <= 'f'
}

// Get int representation of provided hex digit.
// Note: Assumes isHex has already been called.
func digitVal(c rune) int {
	if '0' <= c && c <= '9' {
		return int(c - '0')
	}
	return int(unicode.ToLower(c) - 'a' + 10)
}

// Read two hex digits from the buffer and decode into an int.
func readByte(r *bufio.Reader) (byte, error) {
	var x byte

	for i := 0; i < 2; i++ {
		c, _, err := r.ReadRune()
		if err != nil {
			return 0, err
		}
		if !isHex(c) {
			return 0, fmt.Errorf("invalid utf-8 escape, incomplete byte")
		}
		x = x*16 + byte(digitVal(c))
	}

	return x, nil
}

// Sentinel error for indicating the presence of a NULL byte or zero code point
// in an escape.
var NULLbyte = errors.New("NULL")

// Convenience helper for checking the next rule in the buffer.
func peek(r *bufio.Reader) rune {
	b, err := r.Peek(1)
	if err != nil {
		return -1
	}
	return rune(b[0])
}

// Convenience helper to read a single rune from the buffer.
// Should only be used after calling peek to ensure there is another rune in the
// buffer.
func next(r *bufio.Reader) rune {
	c, _, _ := r.ReadRune() // nolint:errcheck
	return c
}

// Decodes unicode code point escapes.
// There are two forms of escapes.
// * %XXXX
// * %{...}
func codePointEscape(r *bufio.Reader) (string, error) {
	var min, max int

	// Is the escape a fixed or variable width code point escape.
	if peek(r) == '{' {
		next(r)
		min, max = 1, 6
	} else {
		min, max = 4, 4
	}

	// Read at least `min` hex digits up to `max`
	var x int
	for n := 0; n < max; n++ {
		if !isHex(peek(r)) {
			if n < min {
				return "", fmt.Errorf("incomplete unicode escape. %d missing digits", min-n)
			}
			break
		}
		x = x*16 + digitVal(next(r))
	}

	if max == 6 {
		if c := next(r); c != '}' {
			return "", fmt.Errorf("incomplete %%{xxxx} escape")
		}
	}

	// stop processing string on zero code point
	if x == 0 {
		return "", NULLbyte
	}

	if x > unicode.MaxRune {
		return "", fmt.Errorf("invalid code point U+%x in unicode escape", x)
	}

	// Surrogate code points are not valid
	if 0xD800 <= x && x <= 0xDFFF {
		return "", fmt.Errorf("invalid surrogate code point U+%x in unicode escape", x)
	}

	return string(rune(x)), nil
}

// Decode sequences of %XX escapes.
// Each byte in the sequence is a byte of a UTF-8 encoded character.
// This escape type will include between 1 and 4 escaped bytes in the form of
// %XX%YY
func utf8Escape(r *bufio.Reader) (string, error) {
	b1, err := readByte(r)
	if err != nil {
		return "", err
	}
	// Identify how many escape bytes need to be read
	n := 0
	switch {
	case b1&(0x80) == 0: // 1 byte (ASCII)
		if b1 == 0 {
			return "", NULLbyte
		}
		return string(b1), nil
	case b1&(0xe0) == 0xc0: // 2 bytes
		n = 2
	case b1&(0xf0) == 0xe0: // 3 bytes
		n = 3
	case b1&(0xf8) == 0xF0: // 4 bytes
		n = 4
	default:
		return "", fmt.Errorf("utf-8 escape has invalid leading byte %x", b1)
	}

	// Read `n` additional byte escape sequences
	bs := []byte{b1}
	for i := 1; i < n; i++ {
		if peek(r) != '%' {
			return "", fmt.Errorf("incomplete utf-8 escape. %d missing bytes", n-i)
		}
		next(r)
		b, err := readByte(r)
		if err != nil {
			return "", err
		}
		bs = append(bs, b)
	}

	c, _ := utf8.DecodeRune(bs)
	if c == utf8.RuneError {
		return "", fmt.Errorf("invalid utf-8 escape")
	}

	return string(c), nil
}
