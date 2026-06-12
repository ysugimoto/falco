package value

import (
	"testing"
	"time"
)

// Fastly evaluates all TIME values in UTC/GMT. These tests guard the invariant
// that a value.Time always holds a UTC instant, regardless of the timezone of
// the time.Time it was constructed/mutated from. This is independent of the
// host machine's TZ because the inputs carry explicit non-UTC locations.
func TestTimeUTCInvariant(t *testing.T) {
	tokyo, err := time.LoadLocation("Asia/Tokyo") // +09:00, no DST
	if err != nil {
		t.Fatalf("failed to load location: %s", err)
	}
	newYork, err := time.LoadLocation("America/New_York") // negative offset
	if err != nil {
		t.Fatalf("failed to load location: %s", err)
	}

	// epoch 0 must always render as the GMT wall clock, never the local one.
	const wantString = "Thu, 01 Jan 1970 00:00:00 GMT"

	inputs := []struct {
		name  string
		input time.Time
	}{
		{name: "UTC", input: time.Unix(0, 0).UTC()},
		{name: "Asia/Tokyo", input: time.Unix(0, 0).In(tokyo)},
		{name: "America/New_York", input: time.Unix(0, 0).In(newYork)},
	}

	for _, tc := range inputs {
		t.Run("NewTime/"+tc.name, func(t *testing.T) {
			v := NewTime(tc.input)
			if v.Value.Location() != time.UTC {
				t.Errorf("NewTime did not normalize location: got %s", v.Value.Location())
			}
			if got := v.String(); got != wantString {
				t.Errorf("NewTime String(): got %q, want %q", got, wantString)
			}
		})

		t.Run("Set/"+tc.name, func(t *testing.T) {
			v := &Time{}
			v.Set(tc.input)
			if v.Value.Location() != time.UTC {
				t.Errorf("Set did not normalize location: got %s", v.Value.Location())
			}
			if got := v.String(); got != wantString {
				t.Errorf("Set String(): got %q, want %q", got, wantString)
			}
		})
	}
}
