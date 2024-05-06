package lexer

type OptionFunc func(o *Option)

type Option struct {
	Filename string
	Customs  map[string]struct{}
	// more field if exists
}

func WithFile(filename string) OptionFunc {
	return func(o *Option) {
		o.Filename = filename
	}
}

func WithCustomTokens(idents ...string) OptionFunc {
	return func(o *Option) {
		for i := range idents {
			o.Customs[idents[i]] = struct{}{}
		}
	}
}

func collect(opts []OptionFunc) *Option {
	o := &Option{
		Filename: "",
		Customs:  make(map[string]struct{}),
	}

	for i := range opts {
		opts[i](o)
	}
	return o
}
