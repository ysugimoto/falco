package lexer

type OptionFunc func(o *Option)

type Option struct {
	Filename string
	// more field if exists
}

func WithFile(filename string) OptionFunc {
	return func(o *Option) {
		o.Filename = filename
	}
}

func collect(opts []OptionFunc) *Option {
	o := &Option{
		Filename: "",
	}

	for i := range opts {
		opts[i](o)
	}
	return o
}
