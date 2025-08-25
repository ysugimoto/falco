package variable

import (
	"time"

	"github.com/ysugimoto/falco/interpreter/value"
)

// Handle ratecounter related variables
// ref: https://www.fastly.com/documentation/guides/concepts/rate-limiting/#using-two-count-periods-vcl-only

func getRateCounterBucketValue(rc *value.Ratecounter, client, window string) value.Value {
	switch window {
	case "10s":
		return &value.Integer{
			Value: rc.Bucket(client, 10*time.Second),
		}
	case "20s":
		return &value.Integer{
			Value: rc.Bucket(client, 20*time.Second),
		}
	case "30s":
		return &value.Integer{
			Value: rc.Bucket(client, 30*time.Second),
		}
	case "40s":
		return &value.Integer{
			Value: rc.Bucket(client, 40*time.Second),
		}
	case "50s":
		return &value.Integer{
			Value: rc.Bucket(client, 50*time.Second),
		}
	case "60s":
		return &value.Integer{
			Value: rc.Bucket(client, 60*time.Second),
		}
	}
	return nil
}

func getRateCounterRateValue(rc *value.Ratecounter, client, window string) value.Value {
	switch window {
	case "1s":
		return &value.Float{
			Value: rc.Rate(client, time.Second),
		}
	case "10s":
		return &value.Float{
			Value: rc.Rate(client, 10*time.Second),
		}
	case "60s":
		return &value.Float{
			Value: rc.Rate(client, 60*time.Second),
		}
	}
	return nil
}
