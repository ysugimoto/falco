package formatter

import "regexp"

var multiLineFeedRegex = regexp.MustCompile(`\n{3,}`)
var replace = "\n\n"

func trimMutipleLineFeeds(lines string) string {
	return multiLineFeedRegex.ReplaceAllString(lines, replace)
}

func formatCommentCharacter(comment string, char rune) string {
	bs := []rune(comment)
	// Sharp-style comment
	switch bs[0] {
	case '#':
		for i := range bs {
			if bs[i] != '#' {
				break
			}
			bs[i] = char
		}
	// Slash-style comment
	case '/':
		// Check inline comment like /* ... */ and return without replacing if so
		if len(bs) < 2 || bs[1] == '*' {
			return string(bs)
		}
		for i := range bs {
			if bs[i] != '/' {
				break
			}
			bs[i] = char
		}
	}

	return string(bs)
}
