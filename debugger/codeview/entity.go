package codeview

import (
	"github.com/ysugimoto/falco/debugger/colors"
)

const hightlightOffset = 3
const heightOffset = 15

type Character struct {
	code  string
	color colors.ColorFunc
}

func (c Character) text() string {
	if c.color != nil {
		return c.color(c.code)
	}
	return c.code
}

type Line []Character

func (l Line) text() string {
	var line string
	for i := range l {
		line += l[i].text()
	}
	return line
}

func (l Line) plainText() string {
	var line string
	for i := range l {
		line += l[i].code
	}
	return line
}
