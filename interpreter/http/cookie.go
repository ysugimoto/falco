package http

import (
	"net/textproto"
	"strings"
)

// http.Cookie representation in this package.
// On VCL, we only use name and value
type Cookie struct {
	Name  string
	Value string
}

func ReadCookie(r *Request, filter string) *Cookie {
	cookies, ok := r.Header[textproto.CanonicalMIMEHeaderKey("Cookie")]
	if !ok {
		return nil
	}
	for _, c := range readCookies(cookies) {
		if c.Name == filter {
			return c
		}
	}
	return nil
}

func ReadCookies(r *Request) []*Cookie {
	cookies, ok := r.Header[textproto.CanonicalMIMEHeaderKey("Cookie")]
	if !ok {
		return []*Cookie{}
	}
	return readCookies(cookies)
}

// Follwing functions striongly respect net/http package's cookie manipulation
func readCookies(cookies [][]HeaderItem) []*Cookie {
	var read []*Cookie

	for i := range cookies {
		for j := range cookies[i] {
			cookie := cookies[i][j]
			name := cookie.Key.StrictString()
			if name == "" {
				continue
			}
			name = textproto.TrimString(name)
			if !isValidCookieName(name) {
				continue
			}
			if cookie.Value == nil {
				continue
			}
			value, ok := parseCookieValue(cookie.Value.StrictString(), true)
			if !ok {
				continue
			}
			read = append(read, &Cookie{
				Name:  name,
				Value: value,
			})
		}
	}
	return read
}

func parseCookieValue(raw string, allowDoubleQuote bool) (string, bool) {
	// Strip the quotes, if present.
	if allowDoubleQuote && len(raw) > 1 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
	}
	for i := 0; i < len(raw); i++ {
		if !isValidCookieValueByte(raw[i]) {
			return "", false
		}
	}
	return raw, true
}

func isValidCookieValueByte(b byte) bool {
	return 0x20 <= b && b < 0x7f && b != '"' && b != ';' && b != '\\'
}

func isValidCookieName(name string) bool {
	if name == "" {
		return false
	}
	return strings.IndexFunc(name, isNotToken) < 0
}
func isNotToken(r rune) bool {
	return !isTokenRune(r)
}

func isTokenRune(r rune) bool {
	i := int(r)
	return i < len(isTokenTable) && isTokenTable[i]
}

var isTokenTable = [127]bool{
	'!':  true,
	'#':  true,
	'$':  true,
	'%':  true,
	'&':  true,
	'\'': true,
	'*':  true,
	'+':  true,
	'-':  true,
	'.':  true,
	'0':  true,
	'1':  true,
	'2':  true,
	'3':  true,
	'4':  true,
	'5':  true,
	'6':  true,
	'7':  true,
	'8':  true,
	'9':  true,
	'A':  true,
	'B':  true,
	'C':  true,
	'D':  true,
	'E':  true,
	'F':  true,
	'G':  true,
	'H':  true,
	'I':  true,
	'J':  true,
	'K':  true,
	'L':  true,
	'M':  true,
	'N':  true,
	'O':  true,
	'P':  true,
	'Q':  true,
	'R':  true,
	'S':  true,
	'T':  true,
	'U':  true,
	'W':  true,
	'V':  true,
	'X':  true,
	'Y':  true,
	'Z':  true,
	'^':  true,
	'_':  true,
	'`':  true,
	'a':  true,
	'b':  true,
	'c':  true,
	'd':  true,
	'e':  true,
	'f':  true,
	'g':  true,
	'h':  true,
	'i':  true,
	'j':  true,
	'k':  true,
	'l':  true,
	'm':  true,
	'n':  true,
	'o':  true,
	'p':  true,
	'q':  true,
	'r':  true,
	's':  true,
	't':  true,
	'u':  true,
	'v':  true,
	'w':  true,
	'x':  true,
	'y':  true,
	'z':  true,
	'|':  true,
	'~':  true,
}
