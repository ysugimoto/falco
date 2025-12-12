package codeview

import (
	"bytes"

	"github.com/ysugimoto/falco/debugger/colors"
)

const hightlightOffset = 3
const heightOffset = 20

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
	var line bytes.Buffer
	for i := range l {
		line.WriteString(l[i].text())
	}
	return line.String()
}

func (l Line) plainText() string {
	var line bytes.Buffer
	for i := range l {
		line.WriteString(l[i].code)
	}
	return line.String()
}
