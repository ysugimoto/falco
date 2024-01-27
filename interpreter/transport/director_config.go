package transport

import (
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/exception"
	flchttp "github.com/ysugimoto/falco/interpreter/http"
)

func getDirectorBackend(
	ctx *context.Context,
	dt string, // director type string
	prop *ast.DirectorBackendObject,
) (*flchttp.DirectorBackend, error) {

	backend := &flchttp.DirectorBackend{}
	for _, p := range prop.Values {
		switch p.Key.Value {
		case "backend":
			if v, ok := p.Value.(*ast.Ident); !ok {
				return nil, exception.Runtime(
					&p.GetMeta().Token,
					"backend value must be percentage prefixed value",
				)
			} else if b, ok := ctx.Backends[v.Value]; !ok {
				return nil, exception.Runtime(&p.GetMeta().Token, "backend '%s' is not found", v.Value)
			} else {
				backend.Backend = b
			}
		case "id":
			if v, ok := p.Value.(*ast.String); !ok {
				return nil, exception.Runtime(&p.GetMeta().Token, "id value must be a string")
			} else {
				backend.Id = v.Value
			}
		case "weight":
			if v, ok := p.Value.(*ast.Integer); !ok {
				return nil, exception.Runtime(&p.GetMeta().Token, "weight value must be an integer")
			} else {
				backend.Weight = int(v.Value)
			}
		default:
			return nil, exception.Runtime(
				&p.GetMeta().Token,
				"Unexpected director backend property '%s' found",
				p.Key.Value,
			)
		}
	}

	// Validate reqired properties
	switch dt {
	case flchttp.DIRECTORTYPE_RANDOM, flchttp.DIRECTORTYPE_HASH, flchttp.DIRECTORTYPE_CLIENT:
		if backend.Weight == 0 {
			return nil, exception.Runtime(
				&prop.GetMeta().Token,
				".weight property must be set when director type is '%s'",
				dt,
			)
		}
	case flchttp.DIRECTORTYPE_CHASH:
		if backend.Id == "" {
			return nil, exception.Runtime(
				&prop.GetMeta().Token,
				".id property must be set when director type is '%s'",
				dt,
			)
		}
	}

	return backend, nil
}

// Note, returns director config setter function
func getDirectorProperty(dt string, prop *ast.DirectorProperty) (func(d *flchttp.Director), error) {
	switch prop.Key.Value {
	case "quorum":
		if dt == flchttp.DIRECTORTYPE_FALLBACK {
			return nil, exception.Runtime(
				&prop.GetMeta().Token,
				".quorum field must not be present in fallback director type",
			)
		}
		if v, ok := prop.Value.(*ast.String); !ok {
			return nil, exception.Runtime(
				&prop.GetMeta().Token,
				"quorum value must be percentage prefixed value",
			)
		} else if n, err := strconv.Atoi(strings.TrimSuffix(v.Value, "%")); err != nil {
			return nil, exception.Runtime(
				&prop.GetMeta().Token,
				"Invalid quorum value '%s' found. Value must be percentage string like '50%%'",
				v.Value,
			)
		} else {
			return func(d *flchttp.Director) {
				d.Quorum = n
			}, nil
		}
	case "retries":
		if dt != flchttp.DIRECTORTYPE_RANDOM {
			return nil, exception.Runtime(
				&prop.GetMeta().Token,
				".retries field must be present only in random director type",
			)
		}
		if v, ok := prop.Value.(*ast.Integer); !ok {
			return nil, exception.Runtime(&prop.GetMeta().Token, "retries value must be integer")
		} else {
			return func(d *flchttp.Director) {
				d.Retries = int(v.Value)
			}, nil
		}
	case "key":
		if dt != flchttp.DIRECTORTYPE_CHASH {
			return nil, exception.Runtime(
				&prop.GetMeta().Token,
				".key field must be present only in chash director type",
			)
		}
		if v, ok := prop.Value.(*ast.Ident); !ok {
			return nil, exception.Runtime(&prop.GetMeta().Token, ".key value must be integer")
		} else if v.Value != "object" && v.Value != "client" {
			return nil, exception.Runtime(&prop.GetMeta().Token, ".key value must be either of object or client")
		} else {
			return func(d *flchttp.Director) {
				d.Key = v.Value
			}, nil
		}
	case "seed":
		if dt != flchttp.DIRECTORTYPE_CHASH {
			return nil, exception.Runtime(
				&prop.GetMeta().Token,
				".seed field must be present only in chash director type",
			)
		}
		if v, ok := prop.Value.(*ast.Integer); !ok {
			return nil, exception.Runtime(&prop.GetMeta().Token, ".seed value must be integer")
		} else {
			return func(d *flchttp.Director) {
				d.Seed = uint32(v.Value)
			}, nil
		}
	case "vnodes_per_node":
		if dt != flchttp.DIRECTORTYPE_CHASH {
			return nil, exception.Runtime(
				&prop.GetMeta().Token,
				".vnodes_per_node field must be present only in chash director type",
			)
		}
		if v, ok := prop.Value.(*ast.Integer); !ok {
			return nil, exception.Runtime(&prop.GetMeta().Token, ".vnodes_per_node value must be integer")
		} else if v.Value > 8_388_608 {
			// vnodes_per_node value is limted under 8,388,608
			// see: https://developer.fastly.com/reference/vcl/declarations/director/#consistent-hashing
			return nil, exception.Runtime(&prop.GetMeta().Token, ".vnodes_per_node value is limited under 8388608")
		} else {
			return func(d *flchttp.Director) {
				d.VNodesPerNode = int(v.Value)
			}, nil
		}
	}
	return nil, exception.Runtime(&prop.GetMeta().Token, "Unexpected director property '%s' found", prop.Key.Value)
}

func GetDirector(ctx *context.Context, decl *ast.DirectorDeclaration) (*flchttp.Director, error) {
	d := &flchttp.Director{
		Name: decl.Name.Value,
		Type: decl.DirectorType.Value,
	}

	// Validate director type
	if _, ok := flchttp.ValidDirectorTypes[decl.DirectorType.Value]; !ok {
		return nil, exception.Runtime(
			&decl.DirectorType.GetMeta().Token,
			"Unexpected director type '%s' provided",
			decl.DirectorType.Value,
		)
	}

	// Parse director properties
	for _, prop := range decl.Properties {
		switch t := prop.(type) {
		case *ast.DirectorBackendObject:
			backend, err := getDirectorBackend(ctx, d.Type, t)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			d.Backends = append(d.Backends, backend)
		case *ast.DirectorProperty:
			setter, err := getDirectorProperty(d.Type, t)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			setter(d)
		default:
			return nil, exception.Runtime(
				&t.GetMeta().Token,
				"Unexpected field expression '%s' found",
				t.String(),
			)
		}
	}

	// Origin-Shielding director which is generated via Fastly would not have any backends
	if len(d.Backends) == 0 && decl.DirectorType.Value != flchttp.DIRECTORTYPE_SHIELD {
		return nil, exception.Runtime(
			&decl.GetMeta().Token,
			"At least one backend must be specified in director '%s'",
			d.Name,
		)
	}

	return d, nil
}
