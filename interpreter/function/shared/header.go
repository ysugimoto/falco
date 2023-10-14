package shared

import "regexp"

// Fastly says following character is valid for header name:
// ! # $ % & ' * + - . 0-9 A-Z ^ _ ` a-z | ~
// And limited to 126 character length.
// @see https://developer.fastly.com/reference/vcl/functions/headers/header-set/#header-names
// And also accepts ":" character to treat as object
var validHeaderCharacters = regexp.MustCompile("^[!#$%&'*+-.0-9A-Z^_`a-z|~:]{1,126}$")

func IsValidHeader(name string) bool {
	return validHeaderCharacters.MatchString(name)
}
