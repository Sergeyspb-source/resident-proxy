//go:build windows

package desktop

import (
	"encoding/binary"
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
)

var win struct {
	mu     sync.Mutex
	url    string
	openCh chan struct{}
	isOpen atomic.Bool
}

func init() {
	win.openCh = make(chan struct{}, 1)
}

// Run показывает иконку в трее и блокирует главный поток до «Выход».
func Run(h Hooks) {
	go windowLoop()
	systray.Run(func() { onReady(h) }, func() {})
}

func onReady(h Hooks) {
	systray.SetTitle("Узел выхода")
	systray.SetTooltip("Узел выхода")
	systray.SetIcon(iconICO())

	mOpen := systray.AddMenuItem("Открыть панель", "Показать окно программы")
	mToggle := systray.AddMenuItemCheckbox("Узел включён", "Принимать подключения", h.Enabled != nil && h.Enabled())
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
		win.mu.Unlock()
		if url == "" {
			continue
		}

		win.isOpen.Store(true)
		w := webview2.NewWithOptions(webview2.WebViewOptions{
			AutoFocus: true,
			WindowOptions: webview2.WindowOptions{
				Title:  "Узел выхода",
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

// iconICO рисует 32x32 зелёный круг с тёмной окантовкой.
func iconICO() []byte {
	const size = 32
	pixels := make([]byte, size*size*4)
	cx, cy := 15.5, 15.5
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx, dy := float64(x)-cx, float64(y)-cy
			d := dx*dx + dy*dy
			var r, g, b, a byte
			switch {
			case d <= 11*11:
				r, g, b, a = 0x43, 0xd1, 0x7a, 0xff
			case d <= 14*14:
				r, g, b, a = 0x14, 0x17, 0x1c, 0xff
			}
			i := ((size - 1 - y) * size + x) * 4
			pixels[i+0] = b
			pixels[i+1] = g
			pixels[i+2] = r
			pixels[i+3] = a
		}
	}

	mask := make([]byte, size*size/8)
	img := make([]byte, 40, 40+len(pixels)+len(mask))
	binary.LittleEndian.PutUint32(img[0:], 40)
	binary.LittleEndian.PutUint32(img[4:], size)
	binary.LittleEndian.PutUint32(img[8:], size*2)
	binary.LittleEndian.PutUint16(img[12:], 1)
	binary.LittleEndian.PutUint16(img[14:], 32)
	binary.LittleEndian.PutUint32(img[20:], uint32(len(pixels)))
	img = append(img, pixels...)
	img = append(img, mask...)

	out := make([]byte, 22, 22+len(img))
	out[2] = 1
	out[4] = 1
	out[6] = size
	out[7] = size
	binary.LittleEndian.PutUint16(out[10:], 1)
	binary.LittleEndian.PutUint16(out[12:], 32)
	binary.LittleEndian.PutUint32(out[14:], uint32(len(img)))
	binary.LittleEndian.PutUint32(out[18:], 22)
	return append(out, img...)
}
