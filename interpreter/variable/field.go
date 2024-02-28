package variable

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ysugimoto/falco/interpreter/value"
)

// Pattern extrapolated from Fastly behavior.
const pattern = `(?i)(?:^|%s)\s*%s(?:(?:\s+)?=(?:\s+)?((?:(?:"(?:(?:\\")|[^"])+)?")|(?:(?:[^%s\s]+)?)))?(?:%s|$|\s+)`

// Escape and inject key / separator into pattern.
func compilePattern(key, sep string) (*regexp.Regexp, error) {
	if sep == "" {
		sep = ","
	}
	sep = regexp.QuoteMeta(sep)
	re, err := regexp.Compile(fmt.Sprintf(pattern, sep, regexp.QuoteMeta(key), sep, sep))
	return re, err
}

// Extract field value from the provided string.
func GetField(subject, key, sep string) *value.String {
	re, err := compilePattern(key, sep)
	if err != nil {
		return &value.String{IsNotSet: true}
	}

	match := re.FindStringSubmatch(subject)
	if len(match) == 0 {
		return &value.String{IsNotSet: true}
	}
	val := match[1]

	// Due to fastly behavior with header values that do not conform to RFC-8941
	// we don't always want to strip quotes.
	if strings.HasPrefix(val, "\"") {
		val = strings.Trim(val, "\"")
	}
	return &value.String{Value: val}
}

// Remove field key from the provided string.
func unsetField(subject, key, sep string) string {
	if sep == "" {
		sep = ","
	}
	re, err := compilePattern(key, sep)
	if err != nil {
		return subject
	}

	loc := re.FindStringIndex(subject)
	switch {
	case len(loc) == 0:
		return subject
	case loc[0] == 0: // found at the beginning of the header drop trailing separator
		return subject[loc[1]:]
	case string(subject[loc[1]-1]) == sep: // found in the middle drop trailing separator
		return subject[:loc[0]] + subject[loc[1]-1:]
	}
	// found at the end drop leading separator
	return subject[:loc[0]]
}

// Set field key in the provided string.
func setField(subject, key string, val value.Value, sep string) string {
	if sep == "" {
		sep = ","
	}
	// When setting a field fastly will look for the first matching key in the
	// string and remove it. The new value is then added at the end.
	// NOTE: If there is more than one matching field key only the first one
	// is removed.
	subject = unsetField(subject, key, sep)
	var kv string

	if value.IsNotSet(val) {
		// Fastly has a bug with how it handles setting a field on an unset
		// header. If the field key length is 1 the field is not set, however
		// for keys of length >1 it sets the key with no value.
		if subject == "" && len(key) == 1 {
			return subject
		}
		kv = key
	} else {
		sVal := val.String()
		// Double quotes are added for values containing whitespace or any of
		// these characters.
		// = @ ( ) [ ] { } ? / \\ ; : ' < > ,
		if regexp.MustCompile(`[\s=@()\[\]{}?/\\;:'<>,]`).MatchString(sVal) {
			escaped := strings.ReplaceAll(sVal, `"`, `\"`)
			// Fastly truncates values at newlines after quoting the value.
			sVal, _, _ = strings.Cut(`"`+escaped+`"`, "\n")
		}
		kv = fmt.Sprintf("%s=%s", key, sVal)
	}

	if subject == "" {
		return kv
	}
	return subject + sep + kv
}
