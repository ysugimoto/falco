package variable

import (
	"time"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Handle ratecounter related variables
// ref: https://www.fastly.com/documentation/guides/concepts/rate-limiting/#using-two-count-periods-vcl-only

func getRateCounterBucketValue(ctx *context.Context, rc *value.Ratecounter, client, window string) (value.Value, error) {
	var duration time.Duration

	switch window {
	case "10s":
		duration = 10 * time.Second
	case "20s":
		duration = 20 * time.Second
	case "30s":
		duration = 30 * time.Second
	case "40s":
		duration = 40 * time.Second
	case "50s":
		duration = 50 * time.Second
	case "60s":
		duration = 50 * time.Second
	default:
		return nil, exception.Runtime(nil, "unexpected window %s found", window)
	}

	// If fixed rate is injected for testing, use it
	if ctx.FixedAccessRate != nil {
		return &value.Integer{
			Value: int64(*ctx.FixedAccessRate * duration.Seconds()),
		}, nil
	}

	return &value.Integer{
		Value: rc.Bucket(client, duration),
	}, nil
}

func getRateCounterRateValue(ctx *context.Context, rc *value.Ratecounter, client, window string) (value.Value, error) {
	var duration time.Duration

	switch window {
	case "1s":
		duration = time.Second
	case "10s":
		duration = 10 * time.Second
	case "60s":
		duration = 60 * time.Second
	default:
		return nil, exception.Runtime(nil, "unexpected window %s found", window)
	}

	// If fixed rate is injected for testing, use it
	if ctx.FixedAccessRate != nil {
		return &value.Float{
			Value: *ctx.FixedAccessRate,
		}, nil
	}

	return &value.Float{
		Value: rc.Rate(client, duration),
	}, nil
}
