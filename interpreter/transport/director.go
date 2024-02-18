package transport

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/exception"
	flchttp "github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/value"
)

func DirectorRequest(
	ctx *context.Context,
	d *flchttp.Director,
) (*flchttp.Request, error) {

	var backend *value.Backend
	var err error

	var ci string
	if ctx.ClientIdentity != nil {
		ci = ctx.ClientIdentity.Value
	} else {
		ci = ctx.Request.RemoteAddr
		if idx := strings.LastIndex(ci, ":"); idx != -1 {
			ci = ci[:idx]
		}
	}
	identity := flchttp.DirectorIdentity{
		RequestHash:    ctx.RequestHash.Value,
		ClientIdentity: ci,
	}

	switch d.Type {
	case flchttp.DIRECTORTYPE_RANDOM:
		backend, err = d.Random()
	case flchttp.DIRECTORTYPE_FALLBACK:
		backend, err = d.Fallback()
	case flchttp.DIRECTORTYPE_HASH:
		backend, err = d.Hash(identity)
	case flchttp.DIRECTORTYPE_CLIENT:
		backend, err = d.Client(identity)
	case flchttp.DIRECTORTYPE_CHASH:
		backend, err = d.ConsistentHash(identity)
	default:
		return nil, exception.System("Unexpected director type '%s' provided", d.Type)
	}

	if err != nil {
		return nil, errors.WithStack(err)
	}
	return BackendRequest(ctx, backend)
}
