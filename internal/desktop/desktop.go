// Пакет desktop — окно-приложение, трей и автозапуск.
package desktop

import "sync"

// Hooks — то, что оболочка вызывает при действиях пользователя.
type Hooks struct {
	URL         string
	Title       string
	Enabled     func() bool
	OnToggle    func(bool)
	ToggleLabel string
}

var launch struct {
	mu   sync.Mutex
	exe  string
	args []string
}

// SetLaunchCommand запоминает, чем именно запускать программу при входе в Windows.
func SetLaunchCommand(exe string, args []string) {
	launch.mu.Lock()
	launch.exe = exe
	launch.args = append([]string(nil), args...)
	launch.mu.Unlock()
}

func launchCommand() (string, []string) {
	launch.mu.Lock()
	defer launch.mu.Unlock()
	return launch.exe, append([]string(nil), launch.args...)
}
