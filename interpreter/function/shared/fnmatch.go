package shared

import "strings"

// Fnmatch reports whether name matches the shell wildcard pattern the way
// glibc's fnmatch(3) does with no flags in the C locale, which is what
// Fastly's querystring.globfilter and querystring.globfilter_except use:
//
//   - matching is bytewise: "?" matches one byte, so it does not match "é"
//   - "*" and "?" also match "/" and a leading "."
//   - "\" escapes the next byte, inside and outside brackets; a trailing "\"
//     never matches
//   - "[...]" supports "!" and "^" negation, ranges, a leading "]" as a
//     literal, ASCII "[:class:]" names, single-byte "[.x.]" collating symbols
//     (also as range ends) and "[=x=]" equivalence classes
//   - a bracket that is never closed makes its "[" an ordinary byte, even when
//     one of its members already matched
//   - some malformed brackets fail the match outright: an unknown class, a
//     collating symbol that is not one byte or not closed, an escape or a range
//     with nothing after it
//   - braces are not special
//
// Verified on Fastly: https://fiddle.fastly.dev/fiddle/ad06064c,
// https://fiddle.fastly.dev/fiddle/e250b311,
// https://fiddle.fastly.dev/fiddle/8581426a and
// https://fiddle.fastly.dev/fiddle/baa33a5f.
//
// To match many names against one pattern, use CompileFnmatch.
func Fnmatch(pattern, name string) bool {
	return CompileFnmatch(pattern).Match(name)
}

// FnmatchPattern is a pattern prepared for repeated matching.
type FnmatchPattern struct {
	p       string
	hasStar bool
	// brackets[pi] caches the bracket expression that starts at offset pi. The
	// slice is allocated on the first bracket lookup, and each entry the first
	// time its offset is tried; offsets that are not "[" stay nil.
	brackets []*bracketCache
}

// bracketCache records, for each name byte, what one bracket expression does
// with it: bracketUnknown until computed, bracketFailed when the byte does not
// match, otherwise the offset of the following element plus one.
type bracketCache [256]int32

const (
	bracketUnknown int32 = 0
	bracketFailed  int32 = -1
)

// CompileFnmatch prepares pattern for Match.
func CompileFnmatch(pattern string) *FnmatchPattern {
	return &FnmatchPattern{p: pattern, hasStar: strings.IndexByte(pattern, '*') >= 0}
}

// Match reports whether name matches the pattern.
//
// Every element other than "*" consumes exactly one byte, so the state of a
// match is a pair of offsets, and each pair is decided once, bottom up: at most
// (len(pattern)+1) * (len(name)+1) cells, each O(1) once its bracket result is
// known. That keeps patterns such as "*a*a*a…*b" from backtracking
// exponentially, as a naive recursive matcher does.
//
// A bracket result is computed the first time a "[" offset meets a given byte
// and reused after that, including by later calls on the same pattern. Each
// such parse can scan the rest of the pattern, so filling the cache costs up to
// O(brackets * distinct name bytes * len(pattern)) over the pattern's lifetime,
// where brackets counts the "[" bytes and distinct name bytes is at most 256.
// The cache holds 1 KiB for each "[" offset that has been tried.
func (m *FnmatchPattern) Match(name string) bool {
	p := m.p
	if !m.hasStar {
		pi := 0
		for i := range len(name) {
			if pi = m.step(pi, name[i]); pi < 0 {
				return false
			}
		}
		return pi == len(p)
	}

	// cur[pi] reports whether p[pi:] matches name[ni:], and next does the same
	// for name[ni+1:]. Offsets inside a bracket expression are never reached
	// from offset 0, so whatever is computed for them is harmless.
	cur := make([]bool, len(p)+1)
	next := make([]bool, len(p)+1)
	cur[len(p)] = true
	for pi := len(p) - 1; pi >= 0; pi-- {
		cur[pi] = p[pi] == '*' && cur[pi+1]
	}
	for ni := len(name) - 1; ni >= 0; ni-- {
		cur, next = next, cur
		cur[len(p)] = false
		for pi := len(p) - 1; pi >= 0; pi-- {
			if p[pi] == '*' {
				cur[pi] = cur[pi+1] || next[pi]
				continue
			}
			to := m.step(pi, name[ni])
			cur[pi] = to >= 0 && next[to]
		}
	}
	return cur[0]
}

// step matches one byte against the element at offset pi, which is not "*",
// and returns the offset of the following element, or -1 on a mismatch.
func (m *FnmatchPattern) step(pi int, ch byte) int {
	p := m.p
	if pi >= len(p) {
		return -1
	}
	switch p[pi] {
	case '?':
		return pi + 1
	case '\\':
		if pi+1 < len(p) && p[pi+1] == ch {
			return pi + 2
		}
		return -1
	case '[':
		cache := m.bracketFor(pi)
		switch cached := cache[ch]; cached {
		case bracketFailed:
			return -1
		case bracketUnknown:
		default:
			return int(cached) - 1
		}
		to := -1
		switch n, result := matchBracket(p[pi+1:], ch); result {
		case bracketMatch:
			to = pi + 1 + n
		case bracketLiteral:
			if ch == '[' {
				to = pi + 1
			}
		default:
		}
		if to < 0 {
			cache[ch] = bracketFailed
		} else {
			cache[ch] = int32(to + 1)
		}
		return to
	default:
		if p[pi] == ch {
			return pi + 1
		}
		return -1
	}
}

// bracketFor returns the cache for the bracket expression at offset pi,
// allocating it on first use.
func (m *FnmatchPattern) bracketFor(pi int) *bracketCache {
	if m.brackets == nil {
		m.brackets = make([]*bracketCache, len(m.p))
	}
	if m.brackets[pi] == nil {
		m.brackets[pi] = new(bracketCache)
	}
	return m.brackets[pi]
}

type bracketResult int

const (
	bracketNoMatch bracketResult = iota
	bracketMatch
	bracketLiteral // never closed: the "[" is an ordinary byte
)

// glibc's limit on a character class name.
const charClassMaxLength = 256

var charClasses = map[string]func(byte) bool{
	"alnum":  func(c byte) bool { return isAlpha(c) || isDigit(c) },
	"alpha":  isAlpha,
	"blank":  func(c byte) bool { return c == ' ' || c == '\t' },
	"cntrl":  func(c byte) bool { return c < 0x20 || c == 0x7f },
	"digit":  isDigit,
	"graph":  func(c byte) bool { return c > 0x20 && c < 0x7f },
	"lower":  func(c byte) bool { return c >= 'a' && c <= 'z' },
	"print":  func(c byte) bool { return c >= 0x20 && c < 0x7f },
	"punct":  func(c byte) bool { return c > 0x20 && c < 0x7f && !isAlpha(c) && !isDigit(c) },
	"space":  func(c byte) bool { return c == ' ' || (c >= '\t' && c <= '\r') },
	"upper":  func(c byte) bool { return c >= 'A' && c <= 'Z' },
	"xdigit": func(c byte) bool { return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') },
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// matchBracket matches ch against the bracket expression that starts at p, just
// after the "[". On bracketMatch it also returns how many bytes of p the
// expression used, through its closing "]". It follows the bracket handling of
// glibc's fnmatch_loop.c for the C locale.
func matchBracket(p string, ch byte) (int, bracketResult) {
	b := &bracketScanner{p: p}
	negate := b.at(0) == '!' || b.at(0) == '^'
	if negate {
		b.i++
	}
	matched, result := b.members(ch)
	if result != bracketMatch {
		return 0, result
	}
	if matched {
		if result = b.skipRest(); result != bracketMatch {
			return 0, result
		}
	}
	if matched == negate {
		return 0, bracketNoMatch
	}
	return min(b.i, len(p)), bracketMatch
}

// bracketScanner walks a bracket expression. at returns 0 past the end of the
// pattern, standing in for the NUL that ends a C string.
type bracketScanner struct {
	p string
	i int
}

func (b *bracketScanner) at(i int) byte {
	if i < len(b.p) {
		return b.p[i]
	}
	return 0
}

// next returns the byte at the cursor and advances past it.
func (b *bracketScanner) next() byte {
	c := b.at(b.i)
	b.i++
	return c
}

// members compares ch with each member in turn. It returns matched=true with
// the cursor just past the matching member, or matched=false with the cursor
// just past the closing "]". A result other than bracketMatch ends the bracket
// early.
func (b *bracketScanner) members(ch byte) (matched bool, result bracketResult) {
	c := b.next()
	for {
		if c == 0 {
			return false, bracketLiteral
		}
		// A class or equivalence class is a whole member and never starts a range.
		if c == '[' && (b.at(b.i) == ':' || b.at(b.i) == '=') {
			hit, isSet, result := b.setMember(ch)
			if result != bracketMatch || hit {
				return hit, result
			}
			if isSet {
				if c = b.next(); c == ']' {
					return false, bracketMatch
				}
				continue
			}
			// Not a set after all: the "[" is an ordinary member.
		}

		var lo byte
		var hit bool
		switch {
		case c == '[' && b.at(b.i) == '.':
			sym, ok := b.collatingSymbol()
			if !ok {
				return false, bracketNoMatch
			}
			lo, hit = b.ordinary(sym, ch, true)
		case c == '\\':
			if b.at(b.i) == 0 {
				return false, bracketNoMatch
			}
			lo, hit = b.ordinary(b.next(), ch, false)
		default:
			lo, hit = b.ordinary(c, ch, false)
		}
		if hit {
			return true, bracketMatch
		}

		c = b.next()
		if c == '-' && b.at(b.i) != ']' {
			inRange, result := b.rangeEnd(lo, ch)
			if result != bracketMatch || inRange {
				return inRange, result
			}
			c = b.next()
		}
		if c == ']' {
			return false, bracketMatch
		}
	}
}

// ordinary compares a single-byte member c with ch unless it starts a range.
// After a collating symbol glibc treats "-]" as a range start too, so
// "[[.a.]-]" matches only "-".
func (b *bracketScanner) ordinary(c, ch byte, symbol bool) (byte, bool) {
	isRange := b.at(b.i) == '-' && b.at(b.i+1) != 0 && (symbol || b.at(b.i+1) != ']')
	return c, !isRange && c == ch
}

// rangeEnd reads the end of a range whose "-" was just consumed and reports
// whether ch falls between lo and that end.
func (b *bracketScanner) rangeEnd(lo, ch byte) (bool, bracketResult) {
	hi := b.next()
	switch {
	case hi == '[' && b.at(b.i) == '.':
		sym, ok := b.collatingSymbol()
		if !ok {
			return false, bracketNoMatch
		}
		hi = sym
	case hi == '\\':
		hi = b.next()
	}
	if hi == 0 {
		return false, bracketNoMatch
	}
	return lo <= ch && ch <= hi, bracketMatch
}

// setMember handles "[:name:]" or "[=x=]" with the cursor on the ":" or "=".
// isSet is false, with the cursor unchanged, when the text has the wrong shape
// and the "[" is just an ordinary member. An unknown or overlong class name
// fails the match.
func (b *bracketScanner) setMember(ch byte) (hit, isSet bool, result bracketResult) {
	if b.at(b.i) == '=' {
		sym, ok := b.equivalenceClass()
		return ok && sym == ch, ok, bracketMatch
	}
	name, ok, tooLong := b.className()
	if tooLong {
		return false, false, bracketNoMatch
	}
	if !ok {
		return false, false, bracketMatch
	}
	member, known := charClasses[name]
	if !known {
		return false, true, bracketNoMatch
	}
	return member(ch), true, bracketMatch
}

// className reads "name:]" after a "[:" whose ":" is at the cursor. It returns
// ok=false, leaving the cursor alone, when this cannot be a class name. tooLong
// reports glibc's length limit, which fails the whole match.
func (b *bracketScanner) className() (name string, ok, tooLong bool) {
	j := b.i
	for n := 0; ; n++ {
		if n == charClassMaxLength {
			return "", false, true
		}
		j++
		c := b.at(j)
		if c == ':' && b.at(j+1) == ']' {
			name = b.p[b.i+1 : j]
			b.i = j + 2
			return name, true, false
		}
		if c < 'a' || c >= 'z' {
			return "", false, false
		}
	}
}

// collatingSymbol reads "x.]" after a "[." whose "." is at the cursor. In the C
// locale only a single byte names a collating element; anything else, or a
// symbol that is never closed, fails the match.
func (b *bracketScanner) collatingSymbol() (byte, bool) {
	start := b.i
	for j := start + 1; ; j++ {
		c := b.at(j)
		if c == '.' && b.at(j+1) == ']' {
			if j-start-1 != 1 {
				return 0, false
			}
			b.i = j + 2
			return b.p[start+1], true
		}
		if c == 0 {
			return 0, false
		}
	}
}

// equivalenceClass reads "x=]" after a "[=" whose "=" is at the cursor. In the
// C locale the class holds just that byte. It returns ok=false, leaving the
// cursor alone, unless the text is exactly one byte followed by "=]".
func (b *bracketScanner) equivalenceClass() (byte, bool) {
	sym := b.at(b.i + 1)
	if sym == 0 || b.at(b.i+2) != '=' || b.at(b.i+3) != ']' {
		return 0, false
	}
	b.i += 4
	return sym, true
}

// skipRest moves the cursor past the closing "]" of a bracket expression that
// already matched. A bracket that is never closed still makes its "[" an
// ordinary byte, while a malformed escape, collating symbol or equivalence
// class fails the match. Class names are only checked for shape here.
func (b *bracketScanner) skipRest() bracketResult {
	for {
		c := b.next()
		switch {
		case c == 0:
			return bracketLiteral
		case c == '\\':
			if b.at(b.i) == 0 {
				return bracketNoMatch
			}
			b.i++
		case c == '[' && b.at(b.i) == ':':
			if _, _, tooLong := b.className(); tooLong {
				return bracketNoMatch
			}
		case c == '[' && b.at(b.i) == '=':
			if _, ok := b.equivalenceClass(); !ok {
				return bracketNoMatch
			}
		case c == '[' && b.at(b.i) == '.':
			if !b.skipCollatingSymbol() {
				return bracketNoMatch
			}
		}
		if c == ']' {
			return bracketMatch
		}
	}
}

// skipCollatingSymbol moves past "….]" after a "[." whose "." is at the cursor,
// without checking the symbol's length.
func (b *bracketScanner) skipCollatingSymbol() bool {
	for j := b.i + 1; ; j++ {
		c := b.at(j)
		if c == 0 {
			return false
		}
		if c == '.' && b.at(j+1) == ']' {
			b.i = j + 2
			return true
		}
	}
}
