package variable

import (
	"time"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Handle ratecounter related variables
// ref: https://www.fastly.com/documentation/guides/concepts/rate-limiting/#using-two-count-periods-vcl-only

func getRateCounterBucketValue(ctx *context.Context, rc *value.Ratecounter, client, window string) value.Value {
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
		return nil
	}

	// If fixed rate is injected for testing, use it
	if ctx.FixedAccessRate != nil {
		return &value.Integer{
			Value: int64(*ctx.FixedAccessRate * duration.Seconds()),
		}
	}

	return &value.Integer{
		Value: rc.Bucket(client, duration),
	}
}

func getRateCounterRateValue(ctx *context.Context, rc *value.Ratecounter, client, window string) value.Value {
	var duration time.Duration

	switch window {
	case "1s":
		duration = time.Second
	case "10s":
		duration = 10 * time.Second
	case "60s":
		duration = 60 * time.Second
	default:
		return nil
	}

	// If fixed rate is injected for testing, use it
	if ctx.FixedAccessRate != nil {
		return &value.Float{
			Value: *ctx.FixedAccessRate,
		}
	}

	return &value.Float{
		Value: rc.Rate(client, duration),
	}
}
