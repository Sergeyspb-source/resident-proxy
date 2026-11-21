//go:build windows

package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"exitnode/internal/buildinfo"
	"exitnode/internal/versionicon"
)

const (
	runKey      = `Software\Microsoft\Windows\CurrentVersion\Run`
	runName     = "exitnode"
	uninstallID = `Software\Microsoft\Windows\CurrentVersion\Uninstall\exitnode`
	assocExt    = `Software\Classes\.exitnode`
	assocProg   = `Software\Classes\Exitnode.Invite`
)

var pendingUninstall string

// Install копирует программу, создаёт ярлыки, автозапуск и записи удаления.
func Install(opts Options) (string, error) {
	dir, err := installDir()
	if err != nil {
		return "", err
	}
	if opts.Uninstall {
		return uninstall(dir)
	}
	if !opts.Agent && !opts.Client {
		return "", errors.New("укажите --agent или --client")
	}

	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	target := filepath.Join(dir, "proxy.exe")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if !samePath(exe, target) {
		if err := copyFile(exe, target); err != nil {
			return "", err
		}
	}

	_ = deleteRun()

	var msg string
	if opts.Agent {
		if opts.Invite == "" {
			return "", errors.New("для узла нужно приглашение: --invite agent.exitnode")
		}
		b, err := os.ReadFile(opts.Invite)
		if err != nil {
			return "", fmt.Errorf("приглашение: %w", err)
		}
		var inv struct {
			Relay       string `json:"relay"`
			Token       string `json:"token"`
			PublicSocks string `json:"public_socks"`
		}
		if err := json.Unmarshal(b, &inv); err != nil || inv.Relay == "" || inv.Token == "" {
			return "", errors.New("файл не похож на приглашение узла")
		}
		cfgPath := filepath.Join(dir, "agent.json")
		cfgJSON, _ := json.MarshalIndent(map[string]string{
			"relay":        inv.Relay,
			"token":        inv.Token,
			"public_socks": inv.PublicSocks,
		}, "", "  ")
		if err := os.WriteFile(cfgPath, cfgJSON, 0o600); err != nil {
			return "", err
		}

		args := `agent -config "` + cfgPath + `" -tray`
		if err := makeShortcut(desktopPath("Exitnode.lnk"), target, args); err != nil {
			return "", err
		}
		if err := setRun(`"` + target + `" ` + args); err != nil {
			return "", err
		}
		if err := setUninstallEntry(dir, target); err != nil {
			return "", err
		}

		_ = exec.Command(target, "agent", "-config", cfgPath, "-tray").Start()
		msg = "Узел установлен и запущен. Ярлык на рабочем столе, автозапуск включён."
	} else {
		if err := makeShortcut(desktopPath("Exitnode Client.lnk"), target, "client"); err != nil {
			return "", err
		}
		if err := setAssociation(target); err != nil {
			return "", err
		}
		if err := setUninstallEntry(dir, target); err != nil {
			return "", err
		}
		msg = "Клиент установлен. Откройте файл .exitnode или ярлык «Exitnode Client» на рабочем столе."
	}
	return msg, nil
}

// FinishUninstall запускает отложенное удаление файлов после закрытия окна.
func FinishUninstall() {
	dir := pendingUninstall
	pendingUninstall = ""
	if dir == "" {
		return
	}
	script := fmt.Sprintf("timeout /t 3 >nul & taskkill /f /im proxy.exe >nul 2>&1 & rmdir /s /q \"%s\"", dir)
	cmd := exec.Command("cmd", "/c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Start()
}

func uninstall(dir string) (string, error) {
	_ = deleteRun()
	_ = deleteUninstallEntry()
	_ = deleteAssociation()
	_ = os.Remove(desktopPath("Exitnode.lnk"))
	_ = os.Remove(desktopPath("Exitnode Client.lnk"))
	pendingUninstall = dir
	return "Удалено. Приложение закроется, файлы удалятся в течение нескольких секунд.", nil
}

func installDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "exitnode"), nil
}

func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o755)
}

func desktopPath(name string) string {
	return filepath.Join(desktopDir(), name)
}

// desktopDir берёт реальный путь рабочего стола: он может быть
// перенаправлен в OneDrive, и %USERPROFILE%\Desktop тогда не существует.
func desktopDir() string {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		if v, _, err := k.GetStringValue("Desktop"); err == nil {
			if expanded, err := registry.ExpandString(v); err == nil {
				v = expanded
			}
			if v != "" {
				return v
			}
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Desktop")
}

// GPT: New shortcuts use a build-specific icon and description, with a stable shortcut name.
func makeShortcut(lnk, target, args string) error {
	icon := filepath.Join(filepath.Dir(target), "exitnode-"+buildinfo.Version+".ico")
	if err := os.WriteFile(icon, versionicon.ICO(buildinfo.Version), 0o644); err != nil {
		return fmt.Errorf("shortcut icon: %w", err)
	}
	ps := fmt.Sprintf(
		`$s=(New-Object -ComObject WScript.Shell).CreateShortcut('%s'); $s.TargetPath='%s'; $s.Arguments='%s'; $s.IconLocation='%s,0'; $s.Description='%s'; $s.Save()`,
		psQuote(lnk), psQuote(target), psQuote(args), psQuote(icon), psQuote("Exitnode v"+buildinfo.Version))
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ярлык: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func psQuote(s string) string { return strings.ReplaceAll(s, "'", "''") }

func setRun(command string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(runName, command)
}

func deleteRun() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(runName); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

func setUninstallEntry(dir, target string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, uninstallID, registry.WRITE)
	if err != nil {
		return err
	}
	defer k.Close()
	_ = k.SetStringValue("DisplayName", "Узел выхода")
	_ = k.SetStringValue("DisplayVersion", buildinfo.Version)
	_ = k.SetStringValue("InstallLocation", dir)
	_ = k.SetStringValue("DisplayIcon", target)
	_ = k.SetStringValue("UninstallString", `"`+target+`" setup --uninstall`)
	_ = k.SetDWordValue("NoModify", 1)
	_ = k.SetDWordValue("NoRepair", 1)
	return nil
}

func deleteUninstallEntry() error {
	return registry.DeleteKey(registry.CURRENT_USER, uninstallID)
}

func setAssociation(target string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, assocExt, registry.WRITE)
	if err != nil {
		return err
	}
	_ = k.SetStringValue("", "Exitnode.Invite")
	k.Close()

	p, _, err := registry.CreateKey(registry.CURRENT_USER, assocProg, registry.WRITE)
	if err != nil {
		return err
	}
	_ = p.SetStringValue("", "Приглашение Exitnode")
	p.Close()

	cmd, _, err := registry.CreateKey(registry.CURRENT_USER, assocProg+`\shell\open\command`, registry.WRITE)
	if err != nil {
		return err
	}
	defer cmd.Close()
	return cmd.SetStringValue("", `"`+target+`" client -invite "%1"`)
}

func deleteAssociation() error {
	_ = registry.DeleteKey(registry.CURRENT_USER, assocProg+`\shell\open\command`)
	_ = registry.DeleteKey(registry.CURRENT_USER, assocProg+`\shell\open`)
	_ = registry.DeleteKey(registry.CURRENT_USER, assocProg+`\shell`)
	_ = registry.DeleteKey(registry.CURRENT_USER, assocProg)
	return registry.DeleteKey(registry.CURRENT_USER, assocExt)
}

var procMessageBox = syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")

// Message показывает простое окно с результатом установки.
func Message(text string) {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString("Узел выхода")
	_, _, _ = procMessageBox.Call(0,
		uintptr(unsafe.Pointer(t)),
		uintptr(unsafe.Pointer(c)),
		0x40)
}
