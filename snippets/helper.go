package snippets

import "regexp"

var invalid *regexp.Regexp = regexp.MustCompile(`\W`)

func TerraformBackendNameSanitizer(name string) string {
	s := invalid.ReplaceAllString(name, "_")
	return s
}
