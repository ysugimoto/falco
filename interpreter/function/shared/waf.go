package shared

import (
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf8"
)

// IsHexDigit checks if byte is a valid hex digit (0-9, a-f, A-F)
func IsHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// HexDigitValue returns numeric value of hex digit
func HexDigitValue(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b - 'a' + 10)
	case b >= 'A' && b <= 'F':
		return int(b - 'A' + 10)
	}
	return 0
}

// ParseHex2 parses 2 hex characters into a byte value
func ParseHex2(s string) (int, bool) {
	if len(s) < 2 {
		return 0, false
	}
	v, err := strconv.ParseUint(s[:2], 16, 8)
	return int(v), err == nil
}

// ParseHex4 parses 4 hex characters into an int value
func ParseHex4(s string) (int, bool) {
	if len(s) < 4 {
		return 0, false
	}
	v, err := strconv.ParseUint(s[:4], 16, 16)
	return int(v), err == nil
}

// ParseHex6 parses up to 6 hex characters into an int value (for CSS decoding)
func ParseHex6(s string) (int, int) {
	val := 0
	count := 0
	for i := 0; i < len(s) && i < 6; i++ {
		if !IsHexDigit(s[i]) {
			break
		}
		val = val*16 + HexDigitValue(s[i])
		count++
	}
	return val, count
}

// NormalizePath removes multiple slashes, . and .. from paths
func NormalizePath(input string, windowsMode bool) string {
	if windowsMode {
		input = strings.ReplaceAll(input, "\\", "/")
	}
	if input == "" {
		return ""
	}

	isAbsolute := strings.HasPrefix(input, "/")
	hasTrailingSlash := strings.HasSuffix(input, "/") && len(input) > 1

	parts := strings.Split(input, "/")
	var stack []string

	for _, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(stack) > 0 && stack[len(stack)-1] != ".." {
				stack = stack[:len(stack)-1]
			} else if !isAbsolute {
				stack = append(stack, "..")
			}
		default:
			stack = append(stack, part)
		}
	}

	result := strings.Join(stack, "/")
	if isAbsolute {
		result = "/" + result
	}
	if hasTrailingSlash && result != "/" && result != "" {
		result += "/"
	}
	return result
}

// decodeUniHex decodes a %uNNNN value according to WAF rules
func decodeUniHex(val int) byte {
	// If in range 0xFF01-0xFF5E (fullwidth ASCII), add 0x20 to bottom byte
	if val >= 0xFF01 && val <= 0xFF5E {
		return byte((val & 0xFF) + 0x20)
	}
	// Otherwise just use lower 8 bits
	return byte(val & 0xFF)
}

// UrlDecodeUni decodes URL with Microsoft %uNNNN support
func UrlDecodeUni(input string, removeNulls bool) string {
	var result strings.Builder
	result.Grow(len(input))
	i := 0
	for i < len(input) {
		if input[i] == '+' {
			result.WriteByte(' ')
			i++
			continue
		}
		if input[i] == '%' {
			// Try %uNNNN first
			if i+5 < len(input) && (input[i+1] == 'u' || input[i+1] == 'U') {
				if hexVal, ok := ParseHex4(input[i+2 : i+6]); ok {
					decoded := decodeUniHex(hexVal)
					if decoded == 0 {
						if removeNulls {
							i += 6
							continue
						}
						return result.String() // Truncate
					}
					result.WriteByte(decoded)
					i += 6
					continue
				}
			}
			// Try %NN
			if i+2 < len(input) {
				if hexVal, ok := ParseHex2(input[i+1 : i+3]); ok {
					if hexVal == 0 {
						if removeNulls {
							i += 3
							continue
						}
						return result.String() // Truncate
					}
					result.WriteByte(byte(hexVal))
					i += 3
					continue
				}
			}
		}
		result.WriteByte(input[i])
		i++
	}
	return result.String()
}

// ParseByteRanges parses a byte range specification like "0-9,65-90"
func ParseByteRanges(spec string) ([]bool, error) {
	allowed := make([]bool, 256)
	if spec == "" {
		return allowed, nil
	}
	ranges := strings.Split(spec, ",")
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		parts := strings.Split(r, "-")
		if len(parts) != 2 {
			// Single value
			val, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil || val < 0 || val > 255 {
				return nil, &ByteRangeError{r}
			}
			allowed[val] = true
			continue
		}
		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || start < 0 || start > 255 {
			return nil, &ByteRangeError{r}
		}
		end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || end < 0 || end > 255 || start > end {
			return nil, &ByteRangeError{r}
		}
		for i := start; i <= end; i++ {
			allowed[i] = true
		}
	}
	return allowed, nil
}

// ByteRangeError represents an invalid byte range
type ByteRangeError struct {
	Range string
}

func (e *ByteRangeError) Error() string {
	return "invalid byte range: " + e.Range
}

// HtmlEntityDecode decodes HTML entities according to WAF rules
func HtmlEntityDecode(input string) string {
	var result strings.Builder
	result.Grow(len(input))
	i := 0
	for i < len(input) {
		if input[i] != '&' {
			result.WriteByte(input[i])
			i++
			continue
		}
		consumed, decoded, ok := parseHtmlEntity(input[i:])
		if ok {
			result.WriteByte(decoded)
			i += consumed
		} else {
			result.WriteByte('&')
			i++
		}
	}
	return result.String()
}

func parseHtmlEntity(s string) (consumed int, decoded byte, ok bool) {
	if len(s) < 2 || s[0] != '&' {
		return 0, 0, false
	}

	// Try &#x (hex numeric)
	if len(s) >= 3 && s[1] == '#' && (s[2] == 'x' || s[2] == 'X') {
		val := 0
		i := 3
		for i < len(s) && IsHexDigit(s[i]) {
			val = val*16 + HexDigitValue(s[i])
			i++
		}
		if i == 3 {
			return 0, 0, false // No hex digits
		}
		if i < len(s) && s[i] == ';' {
			i++
		}
		return i, byte(val & 0xFF), true
	}

	// Try &# (decimal numeric)
	if len(s) >= 3 && s[1] == '#' {
		val := 0
		i := 2
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			val = val*10 + int(s[i]-'0')
			i++
		}
		if i == 2 {
			return 0, 0, false // No digits
		}
		if i < len(s) && s[i] == ';' {
			i++
		}
		return i, byte(val & 0xFF), true
	}

	// Try named entities
	entities := map[string]byte{
		"quot": '"',
		"amp":  '&',
		"lt":   '<',
		"gt":   '>',
		"nbsp": 0xA0,
	}

	for name, char := range entities {
		if len(s) < len(name)+1 || strings.ToLower(s[1:len(name)+1]) != name {
			continue
		}
		consumed := len(name) + 1
		if len(s) > consumed && s[consumed] == ';' {
			consumed++
		}
		return consumed, char, true
	}

	return 0, 0, false
}

// CssDecode decodes CSS 2.x escape sequences (ModSecurity compatible)
func CssDecode(input string) string {
	var result strings.Builder
	result.Grow(len(input))
	i := 0
	for i < len(input) {
		if input[i] != '\\' {
			if input[i] != 0 {
				result.WriteByte(input[i])
			}
			i++
			continue
		}
		// Backslash found
		if i+1 >= len(input) {
			// Backslash at end - ignore it
			i++
			continue
		}
		// Parse CSS escape - up to 6 hex digits
		j := i + 1
		hexCount := 0
		for k := 0; k < 6 && j+k < len(input) && IsHexDigit(input[j+k]); k++ {
			hexCount++
		}
		switch {
		case hexCount > 0:
			hexStr := input[j : j+hexCount]
			c := cssDecode6HexDigits(hexStr)
			j += hexCount
			// Skip optional whitespace after hex (space, tab, newline, carriage return, form feed)
			if j < len(input) && (input[j] == ' ' || input[j] == '\t' || input[j] == '\n' || input[j] == '\r' || input[j] == '\f') {
				j++
			}
			if c != 0 {
				result.WriteByte(c)
			}
			i = j
		case input[j] == '\n':
			// Backslash + newline is ignored (CSS line continuation)
			i = j + 1
		default:
			// Escape of non-hex character - output the character (skip backslash)
			if input[j] != 0 {
				result.WriteByte(input[j])
			}
			i = j + 1
		}
	}
	return result.String()
}

// cssDecode6HexDigits decodes up to 6 hex digits according to ModSecurity CSS decoding rules
func cssDecode6HexDigits(hexStr string) byte {
	n := len(hexStr)
	if n == 0 {
		return 0
	}
	// Get the low byte (last 2 hex digits)
	var c byte
	if n >= 2 {
		c = byte((HexDigitValue(hexStr[n-2]) << 4) | HexDigitValue(hexStr[n-1]))
	} else {
		c = byte(HexDigitValue(hexStr[0]))
	}
	// Fullwidth ASCII check for 4, 5, or 6 hex digits
	// Range 0xff01-0xff5e needs 0x20 added to the low byte
	if n >= 4 {
		// Check if high byte indicates fullwidth (0xFF)
		// For 4 digits: chars 0,1 are the high byte
		// For 5 digits: char 0 should be '0', chars 1,2 are high byte
		// For 6 digits: chars 0,1 should be '00', chars 2,3 are high byte
		doFullCheck := false
		switch n {
		case 4:
			doFullCheck = true
		case 5:
			doFullCheck = (hexStr[0] == '0')
		case 6:
			doFullCheck = (hexStr[0] == '0' && hexStr[1] == '0')
		}
		if doFullCheck && c > 0x00 && c < 0x5f {
			// Check if the "high byte" hex chars are 'ff' or 'FF'
			h1 := hexStr[n-4]
			h2 := hexStr[n-3]
			if (h1 == 'f' || h1 == 'F') && (h2 == 'f' || h2 == 'F') {
				c += 0x20
			}
		}
	}
	return c
}

// JsDecode decodes JavaScript escape sequences (ModSecurity compatible)
func JsDecode(input string) string {
	var result strings.Builder
	result.Grow(len(input))
	i := 0
	for i < len(input) {
		if input[i] != '\\' {
			if input[i] != 0 {
				result.WriteByte(input[i])
			}
			i++
			continue
		}
		if i+1 >= len(input) {
			result.WriteByte(input[i])
			i++
			continue
		}
		i = jsDecodeEscape(input, i, &result)
	}
	return result.String()
}

func jsDecodeEscape(input string, i int, result *strings.Builder) int {
	next := input[i+1]
	switch next {
	case 'a':
		result.WriteByte('\a')
		return i + 2
	case 'b':
		result.WriteByte('\b')
		return i + 2
	case 'f':
		result.WriteByte('\f')
		return i + 2
	case 'n':
		result.WriteByte('\n')
		return i + 2
	case 'r':
		result.WriteByte('\r')
		return i + 2
	case 't':
		result.WriteByte('\t')
		return i + 2
	case 'v':
		result.WriteByte('\v')
		return i + 2
	case 'x':
		return jsDecodeHexEscape(input, i, result)
	case 'u':
		return jsDecodeUnicodeEscape(input, i, result)
	case '0', '1', '2', '3', '4', '5', '6', '7':
		return jsDecodeOctalEscape(input, i, result)
	default:
		if next != 0 {
			result.WriteByte(next)
		}
		return i + 2
	}
}

func jsDecodeHexEscape(input string, i int, result *strings.Builder) int {
	if i+3 < len(input) && IsHexDigit(input[i+2]) && IsHexDigit(input[i+3]) {
		v := byte((HexDigitValue(input[i+2]) << 4) | HexDigitValue(input[i+3]))
		if v != 0 {
			result.WriteByte(v)
		}
		return i + 4
	}
	result.WriteByte(input[i+1])
	return i + 2
}

func jsDecodeUnicodeEscape(input string, i int, result *strings.Builder) int {
	if i+5 < len(input) && IsHexDigit(input[i+2]) && IsHexDigit(input[i+3]) &&
		IsHexDigit(input[i+4]) && IsHexDigit(input[i+5]) {

		v := byte((HexDigitValue(input[i+4]) << 4) | HexDigitValue(input[i+5]))
		if v > 0x00 && v < 0x5f &&
			(input[i+2] == 'f' || input[i+2] == 'F') &&
			(input[i+3] == 'f' || input[i+3] == 'F') {

			v += 0x20
		}
		if v != 0 {
			result.WriteByte(v)
		}
		return i + 6
	}
	result.WriteByte(input[i+1])
	return i + 2
}

func jsDecodeOctalEscape(input string, i int, result *strings.Builder) int {
	j := 0
	for j < 3 && i+1+j < len(input) && isOctalDigit(input[i+1+j]) {
		j++
	}
	if j > 0 {
		if j == 3 && input[i+1] > '3' {
			j = 2
		}
		var val byte
		for k := 0; k < j; k++ {
			val = val*8 + (input[i+1+k] - '0')
		}
		if val != 0 {
			result.WriteByte(val)
		}
		return i + 1 + j
	}
	result.WriteByte(input[i+1])
	return i + 2
}

func isOctalDigit(b byte) bool {
	return b >= '0' && b <= '7'
}

// Utf8ToHex converts UTF-8 to %uXXXXXX format
// Printable ASCII (32-126) except '%' passes through, everything else is hex-encoded
func Utf8ToHex(input string) string {
	var result strings.Builder
	for _, r := range input {
		if r >= 0x20 && r <= 0x7E && r != '%' {
			result.WriteRune(r)
		} else {
			result.WriteString(formatUnicodeHex(r))
		}
	}
	return result.String()
}

func formatUnicodeHex(r rune) string {
	return "%u" + string(hexChar((int(r)>>20)&0xF)) +
		string(hexChar((int(r)>>16)&0xF)) +
		string(hexChar((int(r)>>12)&0xF)) +
		string(hexChar((int(r)>>8)&0xF)) +
		string(hexChar((int(r)>>4)&0xF)) +
		string(hexChar(int(r)&0xF))
}

func hexChar(n int) byte {
	if n < 10 {
		return byte('0' + n)
	}
	return byte('a' + n - 10)
}

// Cmdline normalizes command line according to WAF rules (ModSecurity compatible)
func Cmdline(input string) string {
	var result strings.Builder
	result.Grow(len(input))
	prevSpace := false
	for i := 0; i < len(input); i++ {
		b := input[i]
		switch b {
		case '"', '\'', '\\', '^':
			// Remove these characters
			continue
		case ' ', ',', ';', '\t', '\r', '\n':
			// Collapse whitespace/separators to single space
			if !prevSpace {
				result.WriteByte(' ')
				prevSpace = true
			}
		case '/', '(':
			// Remove space before / or (
			if prevSpace {
				s := result.String()
				result.Reset()
				result.WriteString(s[:len(s)-1])
			}
			result.WriteByte(b)
			prevSpace = false
		default:
			// Lowercase ASCII letters
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			result.WriteByte(b)
			prevSpace = false
		}
	}
	return result.String()
}

// ValidateUtf8 checks if string is valid UTF-8
func ValidateUtf8(input string) bool {
	return utf8.ValidString(input)
}

// ValidateUrlEncoding validates URL percent encoding
func ValidateUrlEncoding(input string) bool {
	for i := 0; i < len(input); i++ {
		if input[i] != '%' {
			continue
		}
		if i+2 >= len(input) {
			return false
		}
		if !IsHexDigit(input[i+1]) || !IsHexDigit(input[i+2]) {
			return false
		}
		i += 2
	}
	return true
}

// Hexencode encodes each byte as two hex characters
func Hexencode(input string) string {
	return hex.EncodeToString([]byte(input))
}
