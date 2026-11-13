package shared

import (
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Expected results come from querystring.globfilter_except on Fastly
// (https://fiddle.fastly.dev/fiddle/ad06064c,
// https://fiddle.fastly.dev/fiddle/e250b311,
// https://fiddle.fastly.dev/fiddle/8581426a and
// https://fiddle.fastly.dev/fiddle/baa33a5f), except rows marked "glibc",
// which follow glibc's fnmatch where those fiddles had no matching name.
func TestFnmatch(t *testing.T) {
	tests := []struct {
		pattern, name string
		want          bool
	}{
		{"k*", "k v", true},
		{"k?v", "k+v", true},
		{"k?v", "k%20v", false},
		{"?", "é", false}, // two bytes
		{"??", "é", true},
		{"*/*", "a/b", true},
		{"*h", ".h", true},
		{"k\\*", "k*", true},
		{"k\\*", "kk", false},
		{"\\\\k", "\\k", true},
		{"\\", "\\", false},   // trailing backslash never matches
		{"k\\", "k\\", false}, // trailing backslash never matches
		{"{k,A}", "{k,A}", true},
		{"{k,A}*", "k", false},
		{"[!k]*", "K", true},
		{"[^k]*", "kA", false},
		{"[]k]*", "]", true},
		{"[]-a]", "]", true},
		{"[]-a]", "_", true},
		{"[a-]*", "-", true},
		{"[z-a]*", "a", false},
		{"[a\\-z]*", "-", true},
		{"[a\\-z]*", "b", false},
		{"[\\]]*", "]", true},
		{"[[]*", "[k]", true},
		{"k[", "k[", true},
		{"[", "[", true}, // glibc
		{"[]", "]", false},
		{"[!!]", "!", false},
		{"[!!]", "z", true},
		{"[[:alpha:]]*", "ab", true},
		{"[[:alpha:]]*", "é", false},
		{"[[:digit:]]*", "9", true},
		{"[[:upper:]]", "K", true},
		{"*[[:punct:]]*", "a-", true},
		{"[[:bogus:]]", "a", false},
		{"[[:alpha:]", "a", false}, // glibc
		{"", "", true}, // glibc
		{"", "a", false},

		// An unterminated bracket is a literal "[" even after a member matched.
		{"[[", "[[", true},
		{"[[", "[", false},
		{"[!a", "[!a", true},
		{"[!a", "b", false},
		{"[a*", "[a-", true},
		{"[a*", "a", false},
		{"[]a", "[]a", true},
		{"*[a", "*[a", true},
		{"[[=a=]", "[a", true},
		{"[[.a.]", "[a", true},
		// ...but these still fail outright.
		{"[a-", "[a-", false},
		{"[a\\", "[a\\", false},
		{"[a[:digit:]", "[a[:digit:]", false},
		{"[a[:bogus:]]", "a", true},
		{"[a[:bogus:]]", "b", false},

		// Collating symbols.
		{"[[.a.]]", "a", true},
		{"[[.a.]]", "a]", false},
		{"[[.].]]", "]", true},
		{"[[.\\.]]", "\\", true},
		{"[[.!.]a]", "!", true},
		{"[[.ab.]]", "a", false},
		{"[[..]]", ".", false},
		{"[[.space.]]", " ", false}, // glibc
		{"[[.a.]-[.z.]]", "x", true},
		{"[[.a.]-z]", "b", true},
		{"[a-[.z.]]", "z", true},
		{"[[.a.]-]", "-", true},
		{"[[.a.]-]", "a", false},
		{"[![.a.]]", "a", false},
		{"[![.a.]]", "b", true},
		{"[[.a]", "a", false},
		{"[[.a.]]]", "a]", true},

		// Equivalence classes.
		{"[[=a=]]", "a", true},
		{"[[=a=]]", "a]", false},
		{"[[=]=]]", "]", true},
		{"[![=a=]]", "b", true},
		{"[[=a=]-z]", "-", true},
		{"[[=a=]-z]", "b", false},
		{"[[=ab=]]", "a]", true}, // not a class: "[" is a member, then "]" is literal
		{"[[=a]", "[", true},

		// Skipping the rest of a bracket after a member matched.
		{"[a[=b]", "a", false},
		{"[a[=b]", "b", true},
		{"[a[.b]", "a", false},
		{"[a[.bc.]]", "a", true},
		{"[a[:x]", "a", true},
		{"[a[.].]]", "a", true},
		{"[a[=]=]]", "a", true},
		{"[a\\]]", "a", true},
		{"[a[:x:]]", "a", true},
		{"[a[=bb=]]", "a", false},
	}
	for _, tt := range tests {
		if got := Fnmatch(tt.pattern, tt.name); got != tt.want {
			t.Errorf("Fnmatch(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
		}
	}
}

// fnmatchReference is the plain recursive matcher, exponential on some
// patterns but obviously faithful to the element-by-element rules. The fast
// matcher must agree with it.
func fnmatchReference(p, n string) bool {
	for p != "" {
		switch p[0] {
		case '*':
			return fnmatchReference(p[1:], n) || (n != "" && fnmatchReference(p, n[1:]))
		case '?':
			if n == "" {
				return false
			}
		case '\\':
			if len(p) < 2 || n == "" || n[0] != p[1] {
				return false
			}
			p = p[1:]
		case '[':
			if n == "" {
				return false
			}
			used, result := matchBracket(p[1:], n[0])
			switch result {
			case bracketMatch:
				p = p[used:]
			case bracketLiteral:
				if n[0] != '[' {
					return false
				}
			default:
				return false
			}
		default:
			if n == "" || n[0] != p[0] {
				return false
			}
		}
		p, n = p[1:], n[1:]
	}
	return n == ""
}

func TestFnmatchAgreesWithReference(t *testing.T) {
	pieces := []string{"a", "b", "-", "]", "[", "!", "^", "\\", "*", "?", ".", ":", "=",
		"[:alpha:]", "[:x:]", "[.a.]", "[.].]", "[=b=]", "[=]=]", "a-z"}
	bytes := "ab[]-.=!\\:z"
	rng := rand.New(rand.NewSource(1))
	for range 50000 {
		var pb, nb strings.Builder
		for range rng.Intn(7) {
			pb.WriteString(pieces[rng.Intn(len(pieces))])
		}
		for range rng.Intn(7) {
			nb.WriteByte(bytes[rng.Intn(len(bytes))])
		}
		pattern, name := pb.String(), nb.String()
		if got, want := Fnmatch(pattern, name), fnmatchReference(pattern, name); got != want {
			t.Fatalf("Fnmatch(%q, %q) = %v, reference says %v", pattern, name, got, want)
		}
	}
}

// adversarialGlob is a failing match that makes a backtracking matcher explore
// every way of splitting name among the stars.
func adversarialGlob(n int) (pattern, name string) {
	return strings.Repeat("*a", n/2) + "*b", strings.Repeat("a", n)
}

func TestFnmatchAdversarial(t *testing.T) {
	start := time.Now()
	for _, n := range []int{30, 300, 3000} {
		pattern, name := adversarialGlob(n)
		if Fnmatch(pattern, name) {
			t.Errorf("Fnmatch(%d-byte adversarial pattern) matched", len(pattern))
		}
		if !Fnmatch(pattern, name+"b") {
			t.Errorf("Fnmatch(%d-byte adversarial pattern) did not match with a final b", len(pattern))
		}
	}
	bracketed := strings.Repeat("*[a]", 500) + "*[b]"
	if Fnmatch(bracketed, strings.Repeat("a", 1000)) {
		t.Error("bracketed adversarial pattern matched")
	}
	// A backtracking matcher takes seconds at n=30 alone.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("adversarial patterns took %s", elapsed)
	}
}

func BenchmarkFnmatchAdversarial(b *testing.B) {
	for _, n := range []int{30, 300, 3000} {
		pattern, name := adversarialGlob(n)
		m := CompileFnmatch(pattern)
		b.Run("n="+strconv.Itoa(n), func(b *testing.B) {
			for b.Loop() {
				m.Match(name)
			}
		})
	}
}

func BenchmarkFnmatchTypical(b *testing.B) {
	m := CompileFnmatch("utm_*")
	for b.Loop() {
		m.Match("utm_campaign")
		m.Match("page")
	}
}

func TestFnmatchCachesBracketResults(t *testing.T) {
	m := CompileFnmatch("[a]*")
	if m.Match("bbb") {
		t.Fatal(`"[a]*" matched "bbb"`)
	}
	if got := m.brackets[0]['b']; got != bracketFailed {
		t.Errorf("failed bracket result for 'b' cached as %d, want bracketFailed (%d)", got, bracketFailed)
	}
	if !m.Match("abb") {
		t.Fatal(`"[a]*" did not match "abb"`)
	}
	if got := m.brackets[0]['a']; got != 3+1 {
		t.Errorf("successful bracket result for 'a' cached as %d, want 4 (offset 3 plus one)", got)
	}
	if got := m.brackets[0]['c']; got != bracketUnknown {
		t.Errorf("untried byte 'c' cached as %d, want bracketUnknown", got)
	}
	// Only offsets holding "[" get a table.
	for pi, cache := range m.brackets {
		if (cache != nil) != (m.p[pi] == '[') {
			t.Errorf("offset %d (%q) has cache=%v", pi, m.p[pi], cache != nil)
		}
	}
}

// unterminatedBrackets makes every "[" scan the rest of the pattern before
// falling back to a literal, which is slow unless results are cached.
func unterminatedBrackets(n int) (pattern, miss, hit string) {
	return strings.Repeat("[", n) + "*", strings.Repeat("a", n), strings.Repeat("[", n) + "tail"
}

func TestFnmatchUnterminatedBracketsAdversarial(t *testing.T) {
	start := time.Now()
	for _, n := range []int{100, 1200, 3000} {
		pattern, miss, hit := unterminatedBrackets(n)
		m := CompileFnmatch(pattern)
		for range 3 { // repeated calls reuse the cache
			if m.Match(miss) {
				t.Errorf("n=%d: matched %d bytes of 'a'", n, n)
			}
			if !m.Match(hit) {
				t.Errorf("n=%d: did not match %d literal '[' and a tail", n, n)
			}
		}
	}
	// Re-parsing each failed bracket made n=1200 alone take seconds.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("unterminated brackets took %s", elapsed)
	}
}

func BenchmarkFnmatchUnterminatedBrackets(b *testing.B) {
	for _, n := range []int{100, 1200} {
		pattern, miss, _ := unterminatedBrackets(n)
		b.Run("first/n="+strconv.Itoa(n), func(b *testing.B) {
			for b.Loop() {
				CompileFnmatch(pattern).Match(miss)
			}
		})
		m := CompileFnmatch(pattern)
		m.Match(miss) // fill the bracket cache before timing reuse
		b.Run("reused/n="+strconv.Itoa(n), func(b *testing.B) {
			for b.Loop() {
				m.Match(miss)
			}
		})
	}
}
