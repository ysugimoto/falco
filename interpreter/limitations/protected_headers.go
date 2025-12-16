package limitations

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

// Fastly proctects some headers.
// The proctcted headers cannot modify (set, unset) in VCL.
// We define header name as lower case to ensure easily.
// see: https://developer.fastly.com/reference/http/http-headers/
var protectedHeaders = map[string]struct{}{
	"proxy-authenticate":  {},
	"proxy-authotization": {},
	"content-length":      {},
	"content-range":       {},
	"te":                  {},
	"trailer":             {},
	"expect":              {},
	"transfer-encoding":   {},
	"upgrade":             {},
	"fastly-ff":           {},
}

func CheckProtectedHeader(name string) error {
	if _, ok := protectedHeaders[strings.ToLower(name)]; !ok {
		return nil
	}
	return errors.WithStack(
		fmt.Errorf("could not modify %s header, this header is protected by Fastly", name),
	)
}
