package tester

import (
	"bytes"
	"io"
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
)

// Testing tag struct.
// The Inverse fields indicates inverse tag match like !prod.
type Tag struct {
	Name    string
	Inverse bool
}

// Define test metadata.
// This struct fields are filled from annotation comments
type Metadata struct {
	Name   string
	Scopes []context.Scope
	Skip   bool
	Tags   []Tag
}

func (m *Metadata) MatchTags(tags []string) bool {
	// If any tags are not specified in test suite, always run
	if len(m.Tags) == 0 {
		return false
	}

	// If any tags are not provided via cli option, check non-inversed tag is specified
	if len(tags) == 0 {
		for _, v := range m.Tags {
			if !v.Inverse {
				return false
			}
		}
		return true
	}

	// Otherwise, compare both tags
	for i := range tags {
		for _, v := range m.Tags {
			var matched bool
			if v.Name == tags[i] {
				matched = !v.Inverse
			} else {
				matched = v.Inverse
			}
			if matched {
				return true
			}
		}
	}

	return false
}

// Find test metadata from annotation comment
func getTestMetadata(sub *ast.SubroutineDeclaration) *Metadata {
	metadata := &Metadata{
		Name:   sub.Name.Value,
		Scopes: []context.Scope{},
		Skip:   false,
		Tags:   []Tag{},
	}

	comments := sub.GetMeta().Leading
	for i := range comments {
		l := strings.TrimLeft(comments[i].Value, " */#")
		if !strings.HasPrefix(l, "@") {
			continue
		}
		// If @suite annotation found, use it as suite name
		if trimmed, found := strings.CutPrefix(l, "@suite:"); found {
			metadata.Name = strings.TrimSpace(trimmed)
			continue
		}

		// If @skip annotation found. mark as skipped test
		if strings.HasPrefix(l, "@skip") {
			metadata.Skip = true
		}

		// Parse testing tags
		if trimmed, found := strings.CutPrefix(l, "@tag:"); found {
			metadata.Tags = parseTestingTags(strings.TrimSpace(trimmed))
		}

		var Scopes []string

		if trimmed, found := strings.CutPrefix(l, "@scope:"); found {
			Scopes = strings.Split(trimmed, ",")
		} else {
			Scopes = strings.Split(strings.TrimPrefix(l, "@"), ",")
		}
		for _, scope := range Scopes {
			s := context.ScopeByString(strings.TrimSpace(scope))
			if s != context.UnknownScope {
				metadata.Scopes = append(metadata.Scopes, s)
			}
		}
	}

	// If test scope is found, return metadata
	if len(metadata.Scopes) > 0 {
		return metadata
	}

	// If we could not determine scope from annotation, try to find from subroutine name.
	switch {
	case strings.HasSuffix(sub.Name.Value, "_recv"):
		metadata.Scopes = append(metadata.Scopes, context.RecvScope)
	case strings.HasSuffix(sub.Name.Value, "_hash"):
		metadata.Scopes = append(metadata.Scopes, context.HashScope)
	case strings.HasSuffix(sub.Name.Value, "_miss"):
		metadata.Scopes = append(metadata.Scopes, context.MissScope)
	case strings.HasSuffix(sub.Name.Value, "_pass"):
		metadata.Scopes = append(metadata.Scopes, context.PassScope)
	case strings.HasSuffix(sub.Name.Value, "_fetch"):
		metadata.Scopes = append(metadata.Scopes, context.FetchScope)
	case strings.HasSuffix(sub.Name.Value, "_deliver"):
		metadata.Scopes = append(metadata.Scopes, context.DeliverScope)
	case strings.HasSuffix(sub.Name.Value, "_error"):
		metadata.Scopes = append(metadata.Scopes, context.ErrorScope)
	case strings.HasSuffix(sub.Name.Value, "_log"):
		metadata.Scopes = append(metadata.Scopes, context.LogScope)
	default:
		// Set RECV scope as default
		metadata.Scopes = append(metadata.Scopes, context.RecvScope)
	}

	return metadata
}

func parseTestingTags(tagValues string) []Tag {
	var tags []Tag

	buf := bytes.Buffer{}
	var inverse bool
	r := strings.NewReader(tagValues)
	for {
		b, err := r.ReadByte()
		if err != nil {
			// The err must be EOF
			if err != io.EOF {
				goto END
			}
			if buf.Len() > 0 {
				tags = append(tags, Tag{
					Name:    buf.String(),
					Inverse: inverse,
				})
			}
			goto END
		}

		switch b {
		case 0x21: // "!"
			inverse = true
		case 0x2C: // ","
			tags = append(tags, Tag{
				Name:    buf.String(),
				Inverse: inverse,
			})
			buf.Reset()
			inverse = false
		case 0x20: // " "
			continue
		default:
			buf.WriteByte(b)
		}
	}
END:

	return tags
}
