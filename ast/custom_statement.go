package ast

// CustomStatement represents user-defined statement.
// The CustomStatement that will be defined externally must be implemented some methods
// to be enable type assertion.
type CustomStatement interface {
	Statement
	Literal() string
	Lint(func(Node)) error
}
