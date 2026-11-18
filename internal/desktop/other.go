//go:build !windows

package desktop

func Run(_ Hooks)            {}
func OpenWindow(_ string)    {}
func AutostartEnabled() bool { return false }
func SetAutostart(_ bool) error {
	return nil
}
