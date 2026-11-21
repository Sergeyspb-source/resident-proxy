package versionicon

import (
	"encoding/binary"
	"image"
	"image/color"
)

// GPT: Generate a versioned icon at native Windows tray and shortcut sizes.
func ICO(version string) []byte {
	sizes := []int{16, 32}
	out := make([]byte, 6+16*len(sizes))
	binary.LittleEndian.PutUint16(out[2:], 1)
	binary.LittleEndian.PutUint16(out[4:], uint16(len(sizes)))
	for i, size := range sizes {
		buf := iconBitmap(Badge(nodeCircle(size), version))
		off := 6 + 16*i
		out[off], out[off+1] = byte(size), byte(size)
		binary.LittleEndian.PutUint16(out[off+4:], 1)
		binary.LittleEndian.PutUint16(out[off+6:], 32)
		binary.LittleEndian.PutUint32(out[off+8:], uint32(len(buf)))
		binary.LittleEndian.PutUint32(out[off+12:], uint32(len(out)))
		out = append(out, buf...)
	}
	return out
}

func nodeCircle(size int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	center := float64(size-1) / 2
	inner, outer := float64(size)*11/32, float64(size)*14/32
	green := color.NRGBA{R: 0x43, G: 0xd1, B: 0x7a, A: 0xff}
	outline := color.NRGBA{R: 0x14, G: 0x17, B: 0x1c, A: 0xff}
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx, dy := float64(x)-center, float64(y)-center
			d := dx*dx + dy*dy
			if d <= inner*inner {
				img.SetNRGBA(x, y, green)
			} else if d <= outer*outer {
				img.SetNRGBA(x, y, outline)
			}
		}
	}
	return img
}

func iconBitmap(img *image.NRGBA) []byte {
	size := img.Bounds().Dx()
	colorBytes := size * size * 4
	maskStride := ((size + 31) / 32) * 4
	headerSize := 40
	buf := make([]byte, headerSize+colorBytes+maskStride*size)
	binary.LittleEndian.PutUint32(buf, uint32(headerSize))
	binary.LittleEndian.PutUint32(buf[4:], uint32(size))
	binary.LittleEndian.PutUint32(buf[8:], uint32(size*2))
	binary.LittleEndian.PutUint16(buf[12:], 1)
	binary.LittleEndian.PutUint16(buf[14:], 32)
	binary.LittleEndian.PutUint32(buf[20:], uint32(colorBytes))
	for y := 0; y < size; y++ {
		row := size - 1 - y
		for x := 0; x < size; x++ {
			p := img.NRGBAAt(x, y)
			pix := headerSize + (row*size+x)*4
			buf[pix], buf[pix+1], buf[pix+2], buf[pix+3] = p.B, p.G, p.R, p.A
			if p.A == 0 {
				buf[headerSize+colorBytes+row*maskStride+x/8] |= 1 << (7 - uint(x%8))
			}
		}
	}
	return buf
}
