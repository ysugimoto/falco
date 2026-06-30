package value

import (
	"strings"
	"time"
)

// ParseRTimeLiteral converts a VCL RTIME literal (e.g. "60s", "8w", "1y") into
// a time.Duration. Units follow Fastly's RTIME spec: ms, s, m, h, d, w, y.
// time.ParseDuration natively understands ms/s/m/h; d (day), w (week) and y
// (year) are expressed as multiples of an hour.
// https://www.fastly.com/documentation/reference/vcl/types/rtime/
func ParseRTimeLiteral(literal string) (time.Duration, error) {
	switch {
	case strings.HasSuffix(literal, "d"):
		d, err := time.ParseDuration(strings.TrimSuffix(literal, "d") + "h")
		return d * 24, err
	case strings.HasSuffix(literal, "w"):
		d, err := time.ParseDuration(strings.TrimSuffix(literal, "w") + "h")
		return d * 24 * 7, err
	case strings.HasSuffix(literal, "y"):
		d, err := time.ParseDuration(strings.TrimSuffix(literal, "y") + "h")
		return d * 24 * 365, err
	default:
		return time.ParseDuration(literal)
	}
}
