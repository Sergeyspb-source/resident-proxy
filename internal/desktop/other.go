//go:build !windows

package desktop

func Run(_ Hooks)              {}
func OpenWindow(_ string)      {}
func AutostartSupported() bool { return false }
func AutostartEnabled() bool   { return false }
func SetAutostart(_ bool) error {
	return nil
}
