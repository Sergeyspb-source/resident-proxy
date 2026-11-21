package versionicon

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestWindowsIconTracksBuildVersion(t *testing.T) {
	old := ICO("0.0.22")
	current := ICO("0.0.23")
	if bytes.Equal(old, current) {
		t.Fatal("version changed without changing the icon")
	}
	if got := binary.LittleEndian.Uint16(current[4:6]); got != 2 {
		t.Fatalf("icon directory contains %d images", got)
	}
	for i, size := range []byte{16, 32} {
		dir := 6 + i*16
		if current[dir] != size || current[dir+1] != size {
			t.Fatalf("unexpected directory size for %d px", size)
		}
		length := int(binary.LittleEndian.Uint32(current[dir+8:]))
		offset := int(binary.LittleEndian.Uint32(current[dir+12:]))
		if offset < 6+2*16 || offset+length > len(current) {
			t.Fatalf("invalid directory bounds for %d px", size)
		}
		if got := binary.LittleEndian.Uint32(current[offset+8:]); got != 2*uint32(size) {
			t.Fatalf("invalid bitmap and mask height for %d px: %d", size, got)
		}
	}
}
