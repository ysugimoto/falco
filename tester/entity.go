package tester

import "github.com/ysugimoto/falco/lexer"

type TestCase struct {
	Name  string
	Error error
	Scope string
	Time  int // msec order
}

type TestResult struct {
	Filename string
	Cases    []*TestCase
	Lexer    *lexer.Lexer
}

func (t *TestResult) IsPassed() bool {
	for i := range t.Cases {
		if t.Cases[i].Error != nil {
			return false
		}
	}
	return true
}

type TestCounter struct {
	Asserts int
	Passes  int
	Fails   []error
}

func NewTestCounter() *TestCounter {
	return &TestCounter{}
}

func (c *TestCounter) Pass() {
	c.Asserts++
	c.Passes++
}

func (c *TestCounter) Fail(err error) {
	c.Asserts++
	c.Fails = append(c.Fails, err)
}

func (c *TestCounter) Reset() {
	c.Asserts = 0
	c.Passes = 0
	c.Fails = []error{}
}
