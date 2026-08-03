package lexer

import (
	"bytes"
	"sync"
)

var pool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

func (l *Lexer) readString() string {
	buf := pool.Get().(*bytes.Buffer) // nolint:errcheck
	defer pool.Put(buf)
	buf.Reset()

	l.readChar()
	for l.char != '"' && l.char != 0x00 {
		buf.WriteRune(l.char)
		l.readChar()
	}

	return buf.String()
}

func (l *Lexer) readBracketString(delimiter string) string {
	var rs []rune
	end := []byte(delimiter + "}")
	l.readChar()
	for l.char != 0x00 {
		if l.char == '"' {
			n, err := l.r.Peek(len(end))
			if err != nil {
				break
			}

			if bytes.Equal(end, n) {
				l.skipBytes(len(end))
				break
			}
		}
		rs = append(rs, l.char)
		l.readChar()
	}

	return string(rs)
}

// readNumber lexes a decimal or hexadecimal numeric literal, reporting whether
// it is a FLOAT and whether it may take an RTIME unit suffix (decimals only).
// Exponent markers are lowercase 'e' (decimal) and 'p' (hex).
func (l *Lexer) readNumber() (literal string, isFloat, rtimeEligible bool) {
	buf := pool.Get().(*bytes.Buffer) // nolint:errcheck
	defer pool.Put(buf)
	buf.Reset()

	// Hexadecimal literal; never RTIME-eligible.
	if l.char == '0' && (l.peekChar() == 'x' || l.peekChar() == 'X') {
		buf.WriteRune(l.char) // '0'
		l.readChar()
		buf.WriteRune(l.char) // 'x' or 'X'
		l.readChar()
		for isHexDigit(l.char) {
			buf.WriteRune(l.char)
			l.readChar()
		}
		if l.char == '.' {
			isFloat = true
			buf.WriteRune(l.char)
			l.readChar()
			for isHexDigit(l.char) {
				buf.WriteRune(l.char)
				l.readChar()
			}
		}
		if l.char == 'p' {
			isFloat = true
			l.readExponent(buf)
		}
		return buf.String(), isFloat, false
	}

	// Decimal literal; RTIME-eligible unless it has an exponent.
	rtimeEligible = true
	for isDecimalDigit(l.char) {
		buf.WriteRune(l.char)
		l.readChar()
	}
	if l.char == '.' {
		isFloat = true
		buf.WriteRune(l.char)
		l.readChar()
		for isDecimalDigit(l.char) {
			buf.WriteRune(l.char)
			l.readChar()
		}
	}
	if l.char == 'e' {
		isFloat = true
		rtimeEligible = false
		l.readExponent(buf)
	}
	return buf.String(), isFloat, rtimeEligible
}

// readExponent consumes the exponent marker, an optional sign, and the digits.
func (l *Lexer) readExponent(buf *bytes.Buffer) {
	buf.WriteRune(l.char) // 'e' or 'p'
	l.readChar()
	if l.char == '+' || l.char == '-' {
		buf.WriteRune(l.char)
		l.readChar()
	}
	for isDecimalDigit(l.char) {
		buf.WriteRune(l.char)
		l.readChar()
	}
}

func (l *Lexer) readEOL() string {
	buf := pool.Get().(*bytes.Buffer) // nolint:errcheck
	defer pool.Put(buf)
	buf.Reset()

	for {
		buf.WriteRune(l.char)
		if l.peekChar() == 0x00 || l.peekChar() == '\n' {
			break
		}
		l.readChar()
	}
	return buf.String()
}

func (l *Lexer) readMultiComment() string {
	buf := pool.Get().(*bytes.Buffer) // nolint:errcheck
	defer pool.Put(buf)
	buf.Reset()

	for l.char != 0x00 {
		if l.char == '*' && l.peekChar() == '/' {
			buf.WriteRune(l.char)
			l.readChar()
			buf.WriteRune(l.char)
			break
		}
		buf.WriteRune(l.char)
		l.readChar()
	}

	return buf.String()
}

func (l *Lexer) readIdentifier() string {
	buf := pool.Get().(*bytes.Buffer) // nolint:errcheck
	defer pool.Put(buf)
	buf.Reset()

	for isLetter(l.char) {
		buf.WriteRune(l.char)
		l.readChar()
	}
	return buf.String()
}
