package linter

type optionFunc func(l *Linter)

func WithCustomLinters(ls ...CustomLinter) optionFunc {
	return func(l *Linter) {
		for i := range ls {
			l.customLinters[ls[i].Literal()] = ls[i]
		}
	}
}
