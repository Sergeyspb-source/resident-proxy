//go:build windows

package desktop

import (
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"fyne.io/systray"
	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows/registry"

	"exitnode/internal/buildinfo"
	"exitnode/internal/versionicon"
)

var win struct {
	mu     sync.Mutex
	url    string
	title  string
	openCh chan struct{}
	isOpen atomic.Bool
}

func init() {
	win.openCh = make(chan struct{}, 1)
}

// Run показывает иконку в трее и блокирует главный поток до «Выход».
func Run(h Hooks) {
	win.mu.Lock()
	win.title = h.Title
	win.mu.Unlock()
	go windowLoop()
	systray.Run(func() { onReady(h) }, func() {})
	if h.OnExit != nil {
		h.OnExit()
	}
}

// GPT: Show the running build in the tray icon and its full tooltip.
func onReady(h Hooks) {
	title := h.Title
	if title == "" {
		title = "Узел выхода"
	}
	title += " v" + buildinfo.Version
	systray.SetTitle(title)
	systray.SetTooltip(title)
	systray.SetIcon(versionicon.ICO(buildinfo.Version))

	mOpen := systray.AddMenuItem("Открыть панель", "Показать окно программы")
	toggleLabel := h.ToggleLabel
	if toggleLabel == "" {
		toggleLabel = "Узел включён"
	}
	mToggle := systray.AddMenuItemCheckbox(toggleLabel, "Принимать подключения", h.Enabled != nil && h.Enabled())
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Выход", "Остановить программу")

	go func() {
		for {
			select {
			case <-mOpen.ClickedCh:
				OpenWindow(h.URL)
			case <-mToggle.ClickedCh:
				next := !mToggle.Checked()
				if next {
					mToggle.Check()
				} else {
					mToggle.Uncheck()
				}
				if h.OnToggle != nil {
					h.OnToggle(next)
				}
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()

	go func() {
		tk := time.NewTicker(time.Second)
		defer tk.Stop()
		for range tk.C {
			if h.Enabled == nil {
				continue
			}
			if h.Enabled() {
				mToggle.Check()
			} else {
				mToggle.Uncheck()
			}
		}
	}()
}

var (
	user32                  = syscall.NewLazyDLL("user32.dll")
	procShowWindow          = user32.NewProc("ShowWindow")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
)

// OpenWindow открывает собственное окно программы с WebView2.
// Повторный вызов при уже открытом окне ничего не делает.
func OpenWindow(url string) {
	win.mu.Lock()
	win.url = url
	win.mu.Unlock()

	if win.isOpen.Load() {
		return
	}
	select {
	case win.openCh <- struct{}{}:
	default:
	}
}

// windowLoop держит отдельный поток с message loop WebView2.
// systray живёт на главном потоке со своим циклом сообщений.
func windowLoop() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	for range win.openCh {
		win.mu.Lock()
		url := win.url
		title := win.title
		win.mu.Unlock()
		if url == "" {
			continue
		}
		if title == "" {
			title = "Узел выхода"
		}

		win.isOpen.Store(true)
		w := webview2.NewWithOptions(webview2.WebViewOptions{
			AutoFocus: true,
			WindowOptions: webview2.WindowOptions{
				Title:  title,
				Width:  720,
				Height: 660,
				IconId: 1,
				Center: true,
			},
		})
		if w == nil {
			win.isOpen.Store(false)
			log.Printf("WebView2 недоступен, открываю окно браузера")
			openBrowserWindow(url)
			continue
		}

		w.Navigate(url)
		if hwnd := w.Window(); hwnd != nil {
			_, _, _ = procShowWindow.Call(uintptr(hwnd), 9) // SW_RESTORE
			_, _, _ = procSetForegroundWindow.Call(uintptr(hwnd))
		}
		w.Run()
		w.Destroy()
		win.isOpen.Store(false)
	}
}

// openBrowserWindow — запасной вариант, если WebView2 не установлен.
// GPT: Edge/Chrome восстанавливают размер прошлого окна и игнорируют
// --window-size, поэтому у панели отдельный профиль.
func openBrowserWindow(url string) {
	candidates := []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		args := []string{"--app=" + url, "--window-size=720,660"}
		if dir, err := os.UserCacheDir(); err == nil {
			profile := filepath.Join(dir, "exitnode", "ui-profile")
			args = append(args, "--user-data-dir="+profile, "--no-first-run", "--no-default-browser-check")
		}
		cmd := exec.Command(path, args...)
		if err := cmd.Start(); err == nil {
			log.Printf("окно открыто через %s", path)
			return
		}
	}
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

const (
	runKey  = `Software\Microsoft\Windows\CurrentVersion\Run`
	runName = "exitnode"
)

func AutostartSupported() bool { return true }

func AutostartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(runName)
	return err == nil
}

func SetAutostart(enabled bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if !enabled {
		if err := k.DeleteValue(runName); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
		return nil
	}

	exe, args := launchCommand()
	if exe == "" {
		return errors.New("неизвестен путь к программе")
	}
	hasTray := false
	for _, a := range args {
		if a == "-tray" {
			hasTray = true
			break
		}
	}
	if !hasTray {
		args = append(args, "-tray")
	}

	cmd := syscall.EscapeArg(exe)
	for _, a := range args {
		cmd += " " + syscall.EscapeArg(a)
	}
	return k.SetStringValue(runName, cmd)
}
