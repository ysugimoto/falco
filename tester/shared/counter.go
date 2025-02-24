package shared

type Counter struct {
	Asserts int `json:"asserts"`
	Passes  int `json:"passes"`
	Fails   int `json:"fails"`
}

func NewCounter() *Counter {
	return &Counter{}
}

func (c *Counter) Pass() {
	c.Asserts++
	c.Passes++
}

func (c *Counter) Fail() {
	c.Asserts++
	c.Fails++
}
