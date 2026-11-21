package versionicon

import (
	"image"
	"image/color"
	"image/draw"
	"strings"
)

var digits = [...]string{
	"111101101101111",
	"010110010010111",
	"111001111100111",
	"111001111001111",
	"101101111001001",
	"111100111001111",
	"111100111101111",
	"111001001001001",
	"111101111101111",
	"111101111001111",
}

// GPT: Use a short numeric badge at tray size; display the full version in the tooltip.
func Badge(source image.Image, version string) *image.NRGBA {
	bounds := source.Bounds()
	img := image.NewNRGBA(image.Rect(0, 0, bounds.Dx(), bounds.Dy()))
	draw.Draw(img, img.Bounds(), source, bounds.Min, draw.Src)
	build := shortVersion(version)
	if build == "" {
		return img
	}
	scale := max(1, min(img.Bounds().Dx(), img.Bounds().Dy())/16)
	width := (4*len(build) - 1) * scale
	left := (img.Bounds().Dx() - width) / 2
	top := img.Bounds().Dy() - 6*scale
	if left < scale || top < 0 {
		return img
	}
	dark := image.NewUniform(color.NRGBA{R: 0x14, G: 0x17, B: 0x1c, A: 0xff})
	white := image.NewUniform(color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff})
	draw.Draw(img, image.Rect(left-scale, top-scale, left+width+scale, top+6*scale), dark, image.Point{}, draw.Src)
	for i, digit := range build {
		glyph := digits[digit-'0']
		for pixel, value := range glyph {
			if value == '1' {
				x := left + (4*i+pixel%3)*scale
				y := top + (pixel/3)*scale
				draw.Draw(img, image.Rect(x, y, x+scale, y+scale), white, image.Point{}, draw.Src)
			}
		}
	}
	return img
}

func shortVersion(version string) string {
	base, _, _ := strings.Cut(version, "-")
	base, _, _ = strings.Cut(base, "+")
	last := base[strings.LastIndex(base, ".")+1:]
	if last == "" {
		return ""
	}
	for _, digit := range last {
		if digit < '0' || digit > '9' {
			return ""
		}
	}
	if len(last) > 3 {
		last = last[len(last)-3:]
	}
	return last
}
