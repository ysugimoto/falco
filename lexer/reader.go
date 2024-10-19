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
	for {
		if l.char == '"' || l.char == 0x00 {
			break
		}
		buf.WriteRune(l.char)
		l.readChar()
	}

	return buf.String()
}

func (l *Lexer) readBracketString() string {
	buf := pool.Get().(*bytes.Buffer) // nolint:errcheck
	defer pool.Put(buf)
	buf.Reset()

	l.readChar()
	for {
		if l.char == 0x00 {
			break
		}
		if l.char == '"' {
			if l.peekChar() == '}' {
				l.readChar()
				break
			}
		}
		buf.WriteRune(l.char)
		l.readChar()
	}

	return buf.String()
}

func (l *Lexer) readNumber() string {
	buf := pool.Get().(*bytes.Buffer) // nolint:errcheck
	defer pool.Put(buf)
	buf.Reset()

	for isDigit(l.char) {
		buf.WriteRune(l.char)
		l.readChar()
	}
	return buf.String()
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

	for {
		if l.char == 0x00 {
			break
		}
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

	for l.isLetter(l.char) {
		buf.WriteRune(l.char)
		l.readChar()
	}
	return buf.String()
}
