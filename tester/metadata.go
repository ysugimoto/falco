package tester

import (
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
)

// Define test metadata.
// This struct fields are filled from annotation comments
type Metadata struct {
	Name   string
	Scopes []context.Scope
	Skip   bool
}

// Find test metadata from annotation comment
func getTestMetadata(sub *ast.SubroutineDeclaration) *Metadata {
	metadata := &Metadata{
		Name:   sub.Name.Value,
		Scopes: []context.Scope{},
		Skip:   false,
	}

	comments := sub.GetMeta().Leading
	for i := range comments {
		l := strings.TrimLeft(comments[i].Value, " */#")
		if !strings.HasPrefix(l, "@") {
			continue
		}
		// If @suite annotation found, use it as suite name
		if strings.HasPrefix(l, "@suite:") {
			metadata.Name = strings.TrimSpace(strings.TrimPrefix(l, "@suite:"))
			continue
		}

		// If @skip annotation found. mark as skipped test
		if strings.HasPrefix(l, "@skip") {
			metadata.Skip = true
		}

		var Scopes []string
		if strings.HasPrefix(l, "@scope:") {
			Scopes = strings.Split(strings.TrimPrefix(l, "@scope:"), ",")
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
