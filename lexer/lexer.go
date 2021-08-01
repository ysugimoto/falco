package lexer

import (
	"bufio"
	"bytes"
	"io"
	"strings"

	"github.com/ysugimoto/falco/token"
)

type Lexer struct {
	r      *bufio.Reader
	char   rune
	line   int
	index  int
	buffer *bytes.Buffer
	stack  []string
	file   string
	peeks  []token.Token
}

func New(r io.Reader, opts ...OptionFunc) *Lexer {
	o := collect(opts)
	l := &Lexer{
		r:      bufio.NewReader(r),
		line:   1,
		buffer: new(bytes.Buffer),
		file:   o.Filename,
	}
	l.readChar()
	return l
}

func NewFromString(input string) *Lexer {
	return New(strings.NewReader(input))
}

func (l *Lexer) readChar() {
	r, _, err := l.r.ReadRune()
	if err != nil {
		l.char = 0x00
		l.index += 1
		return
	}
	if l.char == 0x0A { // LF
		l.NewLine()
	}
	l.index += 1
	l.char = r
	l.buffer.WriteRune(r)
}

func (l *Lexer) peekChar() rune {
	b, err := l.r.Peek(1)
	if err != nil {
		return 0x00
	}
	return rune(b[0])
}

func (l *Lexer) NewLine() {
	l.stack = append(l.stack, strings.TrimRight(l.buffer.String(), "\n"))
	l.buffer = new(bytes.Buffer)
	l.index = 0
	l.line++
}

func (l *Lexer) GetLine(n int) (string, bool) {
	if n < 1 || n > len(l.stack) {
		return "", false
	}
	return l.stack[n-1], true
}

func (l *Lexer) PeekToken() token.Token {
	t := l.NextToken()
	// peek token stack works FIFO queue
	l.peeks = append(l.peeks, t)
	return t
}

// nolint: funlen,gocognit,gocyclo
func (l *Lexer) NextToken() token.Token {
	var t token.Token

	// if peek stack exists, dequeue from it
	if len(l.peeks) > 0 {
		t, l.peeks = l.peeks[0], l.peeks[1:]
		return t
	}

	l.skipWhitespace()

	index, line := l.index, l.line
	switch l.char {
	case '=':
		if l.peekChar() == '=' {
			l.readChar()
			t = newToken(token.EQUAL, l.char, line, index)
			t.Literal = "=="
		} else {
			t = newToken(token.ASSIGN, l.char, line, index)
		}
	case '-':
		if l.peekChar() == '=' {
			l.readChar()
			t = newToken(token.SUBTRACTION, l.char, line, index)
			t.Literal = "-="
		} else {
			t = newToken(token.MINUS, l.char, line, index)
		}
	case '{':
		// VCL allows bracket enclosed string like {" foobar "},
		// it is convenient to make string that includes whitespace, TAB, etc.
		// So, lexer should lex it.
		if l.peekChar() == '"' {
			l.readChar()
			t = newToken(token.STRING, l.char, line, index)
			t.Literal = l.readBracketString()
			t.Offset = 4 // {" and "}
		} else {
			t = newToken(token.LEFT_BRACE, l.char, line, index)
		}
	case '}':
		t = newToken(token.RIGHT_BRACE, l.char, line, index)
	case '(':
		t = newToken(token.LEFT_PAREN, l.char, line, index)
	case ')':
		t = newToken(token.RIGHT_PAREN, l.char, line, index)
	case '[':
		t = newToken(token.LEFT_BRACKET, l.char, line, index)
	case ']':
		t = newToken(token.RIGHT_BRACKET, l.char, line, index)
	case '"':
		t = newToken(token.STRING, l.char, line, index)
		t.Literal = l.readString()
		t.Offset = 2 // a couple of "
	case ';':
		t = newToken(token.SEMICOLON, l.char, line, index)
	case '.':
		t = newToken(token.DOT, l.char, line, index)
	case ',':
		t = newToken(token.COMMA, l.char, line, index)
	case '/':
		switch l.peekChar() {
		case '=':
			l.readChar()
			t = newToken(token.DIVISION, l.char, line, index)
			t.Literal = "/="
		case '/':
			t = newToken(token.COMMENT, l.char, line, index)
			t.Literal = l.readEOL()
		case '*': // "/*"
			t = newToken(token.COMMENT, l.char, line, index)
			t.Literal = l.readMultiComment()
		default:
			t = newToken(token.SLASH, l.char, line, index)
		}
	case '#':
		t = newToken(token.COMMENT, l.char, line, index)
		t.Literal = l.readEOL()
	case '|':
		switch l.peekChar() {
		case '|': // "||"
			l.readChar()
			if l.peekChar() == '=' { // "||="
				l.readChar()
				t = newToken(token.LOGICAL_OR, l.char, line, index)
				t.Literal = "||="
			} else { // "||"
				t = newToken(token.OR, l.char, line, index)
				t.Literal = "||"
			}
		case '=': // "|="
			l.readChar()
			t = newToken(token.BITWISE_OR, l.char, line, index)
			t.Literal = "|="
		}
	case '&':
		switch l.peekChar() {
		case '&': // "&&"
			l.readChar()
			if l.peekChar() == '=' { // "&&="
				l.readChar()
				t = newToken(token.LOGICAL_AND, l.char, line, index)
				t.Literal = "&&="
			} else { // "&&"
				t = newToken(token.AND, l.char, line, index)
				t.Literal = "&&"
			}
		case '=': // "|="
			l.readChar()
			t = newToken(token.BITWISE_AND, l.char, line, index)
			t.Literal = "&="
		}
	case '^':
		if l.peekChar() == '=' { // "^="
			l.readChar()
			t = newToken(token.BITWISE_XOR, l.char, line, index)
			t.Literal = "^="
		}
	case '+':
		if l.peekChar() == '=' {
			l.readChar()
			t = newToken(token.ADDITION, l.char, line, index)
		} else {
			// NOTE: The "+" character is not used for arithmetic operator in VCL,
			// just use for explicit string concatenation.
			t = newToken(token.PLUS, l.char, line, index)
		}
	case '>':
		switch l.peekChar() {
		case '>': // ">>"
			l.readChar()
			if l.peekChar() == '=' { // ">>="
				l.readChar()
				t = newToken(token.RIGHT_SHIFT, l.char, line, index)
				t.Literal = ">>="
			}
		case '=': // ">="
			l.readChar()
			t = newToken(token.GREATER_THAN_EQUAL, l.char, line, index)
			t.Literal = ">="
		default:
			t = newToken(token.GREATER_THAN, l.char, line, index)
		}
	case '<':
		switch l.peekChar() {
		case '<': // "<<"
			l.readChar()
			if l.peekChar() == '=' { // "<<="
				l.readChar()
				t = newToken(token.LEFT_SHIFT, l.char, line, index)
				t.Literal = "<<="
			}
		case '=': // ">="
			l.readChar()
			t = newToken(token.LESS_THAN_EQUAL, l.char, line, index)
			t.Literal = "<="
		default:
			t = newToken(token.LESS_THAN, l.char, line, index)
		}
	case '%':
		index := l.index
		if l.peekChar() == '=' { // "%="
			l.readChar()
			t = newToken(token.REMAINDER, l.char, line, index)
			t.Literal = "%="
		}
	case ':':
		t = newToken(token.COLON, l.char, line, index)
	case '~':
		t = newToken(token.REGEX_MATCH, l.char, line, index)
	case '!':
		switch l.peekChar() {
		case '=': // "!="
			l.readChar()
			t = newToken(token.NOT_EQUAL, l.char, line, index)
			t.Literal = "!="
		case '~': // "!~"
			l.readChar()
			t = newToken(token.NOT_REGEX_MATCH, l.char, line, index)
			t.Literal = "!~"
		default:
			t = newToken(token.NOT, l.char, line, index)
		}
	case '*':
		if l.peekChar() == '=' { // "*="
			l.readChar()
			t = newToken(token.MULTIPLICATION, l.char, line, index)
			t.Literal = "*="
		}
	case 0x00: // EOF
		t.Literal = ""
		t.Type = token.EOF
		t.Line = line
		t.Position = index
	case 0x0A: // '\n'
		t = newToken(token.LF, l.char, line, index)
	default:
		switch {
		case l.isLetter(l.char):
			literal := l.readIdentifier()

			// Read more neighbor digit, dot, hyphen and colon character
			// in order to lex digit contained identifier like "version4", "req.http.Cookie:session" string
			for l.char == '-' || l.char == '.' || l.char == ':' || isDigit(l.char) {
				literal += string(l.char)
				l.readChar()
				literal += l.readIdentifier()
			}

			switch literal {
			case "rol":
				if l.char == '=' { // "rol="
					t = newToken(token.LEFT_ROTATE, l.char, line, index)
					t.Literal = "rol="
				} else {
					t.Literal = literal
					t.Type = token.LookupIdent(t.Literal)
					t.Line = line
					t.Position = index
					t.File = l.file
					return t
				}
			case "ror":
				if l.char == '=' { // "ror="
					t = newToken(token.RIGHT_ROTATE, l.char, line, index)
					t.Literal = "ror="
				} else {
					t.Literal = literal
					t.Type = token.LookupIdent(t.Literal)
					t.Line = line
					t.Position = index
					t.File = l.file
					return t
				}
			default:
				t.Literal = literal
				t.Type = token.LookupIdent(t.Literal)
				t.Line = line
				t.Position = index
				t.File = l.file
				return t
			}
		case isDigit(l.char):
			num := l.readNumber()
			// VCL has special type of "RTIME", it indicates relative-time.
			// To parse it, we look up unit string after digit Literal
			// and if "ms", "m", "s", "d", "y" character is found, it deals with RTIME token.
			// https://developer.fastly.com/reference/vcl/types/rtime/
			switch l.char {
			case 'm':
				if l.peekChar() == 's' { // "ms"
					l.readChar()
					t = newToken(token.RTIME, l.char, line, index)
					t.Literal = num + "ms" // millisecond
				} else {
					t = newToken(token.RTIME, l.char, line, index)
					t.Literal = num + "m" // month
				}
			case 's', 'h', 'd', 'y': // second, hour, day, year
				t = newToken(token.RTIME, l.char, line, index)
				t.Literal = num + string(l.char)
			case '%':
				// Also "%" is special character which indicates persentage.
				// Usually it will be used on director.quorum field value and it's okey to treat as string token.
				t = newToken(token.STRING, l.char, line, index)
				t.Literal = num + "%"
			default:
				// If literal contains ".", token should be FLOAT
				if strings.Count(num, ".") == 1 {
					t = newToken(token.FLOAT, l.char, line, index)
				} else {
					t = newToken(token.INT, l.char, line, index)
				}
				t.Literal = num
				t.File = l.file
				return t
			}
		default:
			t = newToken(token.ILLEGAL, l.char, line, index)
		}
	}

	l.readChar()
	t.File = l.file
	return t
}

func (l *Lexer) skipWhitespace() {
	for l.char == ' ' || l.char == '\t' || l.char == '\r' {
		l.readChar()
	}
}

func (l *Lexer) readString() string {
	var isEscape bool
	var rs []rune
	l.readChar()
	for {
		if (l.char == '"' && !isEscape) || l.char == 0x00 {
			break
		}
		// escape sequence
		if l.char == 0x5C {
			if l.peekChar() != 0x5C {
				isEscape = true
			}
			rs = append(rs, l.char)
			l.readChar()
			continue
		}
		isEscape = false
		rs = append(rs, l.char)
		l.readChar()
	}

	return string(rs)
}

func (l *Lexer) readBracketString() string {
	var isEscape bool
	var rs []rune
	l.readChar()
	for {
		if l.char == 0x00 {
			break
		}
		if l.char == '"' {
			if isEscape {
				isEscape = false
				rs = append(rs, l.char)
				l.readChar()
				continue
			}
			if l.peekChar() == '}' {
				l.readChar()
				break
			}
		}
		// escape sequence
		if l.char == 0x5C {
			if l.peekChar() != 0x5C {
				isEscape = true
			}
			l.readChar()
			continue
		}

		if isEscape {
			rs = append(rs, '\\')
		}
		rs = append(rs, l.char)
		l.readChar()
		isEscape = false
	}

	return string(rs)
}

func (l *Lexer) readNumber() string {
	var rs []rune
	for isDigit(l.char) {
		rs = append(rs, l.char)
		l.readChar()
	}
	return string(rs)
}

func (l *Lexer) readEOL() string {
	var rs []rune
	for {
		rs = append(rs, l.char)
		if l.peekChar() == 0x00 || l.peekChar() == '\n' {
			break
		}
		l.readChar()
	}
	return string(rs)
}

func (l *Lexer) readMultiComment() string {
	var rs []rune
	for {
		if l.char == 0x00 {
			break
		}
		if l.char == '*' && l.peekChar() == '/' {
			rs = append(rs, l.char)
			l.readChar()
			rs = append(rs, l.char)
			break
		}
		rs = append(rs, l.char)
		l.readChar()
	}

	return string(rs)
}

func (l *Lexer) readIdentifier() string {
	var rs []rune
	for l.isLetter(l.char) {
		rs = append(rs, l.char)
		l.readChar()
	}
	return string(rs)
}

func (l *Lexer) isLetter(r rune) bool {
	// Letter allows "-", "." and ":" character to parse ident http header name like `req.http.X-Forwarded-For`
	// but in some name definitions (e.g. acl name, backend name), parser must check "-" IS NOT included.
	// return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || r == '_' || r == '-' || r == '.' || r == ':'
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '_'
}

func isDigit(r rune) bool {
	// Digit allows "." character to parse literal is INTEGER of FLOAT.
	return (r >= '0' && r <= '9') || r == '.'
}

func newToken(tokenType token.TokenType, literal rune, line, index int) token.Token {
	return token.Token{
		Type:     tokenType,
		Literal:  string(literal),
		Line:     line,
		Position: index,
	}
}
