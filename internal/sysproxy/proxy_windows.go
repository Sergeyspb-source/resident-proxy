//go:build windows

// Р В РЎСџР В Р’В°Р В РЎвЂќР В Р’ВµР РЋРІР‚С™ sysproxy Р В Р вЂ Р В РЎвЂќР В Р’В»Р РЋР вЂ№Р РЋРІР‚РЋР В Р’В°Р В Р’ВµР РЋРІР‚С™ Р РЋР С“Р В РЎвЂР РЋР С“Р РЋРІР‚С™Р В Р’ВµР В РЎВР В Р вЂ¦Р РЋРІР‚в„–Р В РІвЂћвЂ“ Р В РЎвЂ”Р РЋР вЂљР В РЎвЂўР В РЎвЂќР РЋР С“Р В РЎвЂ Windows Р В РЎвЂ Р В Р вЂ Р В РЎвЂўР В Р’В·Р В Р вЂ Р РЋР вЂљР В Р’В°Р РЋРІР‚В°Р В Р’В°Р В Р’ВµР РЋРІР‚С™ Р В РЎвЂ”Р РЋР вЂљР В Р’ВµР В Р’В¶Р В Р вЂ¦Р В РЎвЂР В Р’Вµ Р В Р вЂ¦Р В Р’В°Р РЋР С“Р РЋРІР‚С™Р РЋР вЂљР В РЎвЂўР В РІвЂћвЂ“Р В РЎвЂќР В РЎвЂ.
// GPT: Р В РўвЂР В РЎвЂўР В Р’В±Р В Р’В°Р В Р вЂ Р В Р’В»Р В Р’ВµР В Р вЂ¦Р В РЎвЂў, Р РЋРІР‚РЋР РЋРІР‚С™Р В РЎвЂўР В Р’В±Р РЋРІР‚в„– Р В РЎвЂќР В Р’В»Р В РЎвЂР В Р’ВµР В Р вЂ¦Р РЋРІР‚С™Р В РЎвЂўР В РЎВ Р В РЎВР В РЎвЂўР В Р’В¶Р В Р вЂ¦Р В РЎвЂў Р В Р’В±Р РЋРІР‚в„–Р В Р’В»Р В РЎвЂў Р В РЎвЂ”Р В РЎвЂўР В Р’В»Р РЋР Р‰Р В Р’В·Р В РЎвЂўР В Р вЂ Р В Р’В°Р РЋРІР‚С™Р РЋР Р‰Р РЋР С“Р РЋР РЏ Р В Р’В±Р В Р’ВµР В Р’В· Р РЋР вЂљР РЋРЎвЂњР РЋРІР‚РЋР В Р вЂ¦Р В РЎвЂўР В РІвЂћвЂ“ Р В Р вЂ¦Р В Р’В°Р РЋР С“Р РЋРІР‚С™Р РЋР вЂљР В РЎвЂўР В РІвЂћвЂ“Р В РЎвЂќР В РЎвЂ Р В Р’В±Р РЋР вЂљР В Р’В°Р РЋРЎвЂњР В Р’В·Р В Р’ВµР РЋР вЂљР В Р’В°.
package sysproxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const regPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

type snapshot struct {
	Server        string  `json:"server"`
	Enable        *uint64 `json:"enable,omitempty"`
	ProxyServer   *string `json:"proxy_server,omitempty"`
	ProxyOverride *string `json:"proxy_override,omitempty"`
}

func Supported() bool { return true }

func backupPath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "exitnode", "sysproxy.json")
}

func readBackup() (*snapshot, error) {
	p := backupPath()
	if p == "" {
		return nil, os.ErrNotExist
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var s snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func writeBackup(s *snapshot) error {
	p := backupPath()
	if p == "" {
		return os.ErrInvalid
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(p, b, 0o600)
}

func openKey() (registry.Key, error) {
	return registry.OpenKey(registry.CURRENT_USER, regPath, registry.QUERY_VALUE|registry.SET_VALUE)
}

// Enable Р РЋР С“Р РЋРІР‚С™Р В Р’В°Р В Р вЂ Р В РЎвЂР РЋРІР‚С™ Р РЋР С“Р В РЎвЂР РЋР С“Р РЋРІР‚С™Р В Р’ВµР В РЎВР В Р вЂ¦Р РЋРІР‚в„–Р В РІвЂћвЂ“ SOCKS-Р В РЎвЂ”Р РЋР вЂљР В РЎвЂўР В РЎвЂќР РЋР С“Р В РЎвЂ Р В Р вЂ¦Р В Р’В° addr Р В РЎвЂ Р В Р’В·Р В Р’В°Р В РЎвЂ”Р В РЎвЂўР В РЎВР В РЎвЂР В Р вЂ¦Р В Р’В°Р В Р’ВµР РЋРІР‚С™ Р В РЎвЂ”Р РЋР вЂљР В Р’ВµР В Р’В¶Р В Р вЂ¦Р В РЎвЂР В Р’Вµ Р В Р’В·Р В Р вЂ¦Р В Р’В°Р РЋРІР‚РЋР В Р’ВµР В Р вЂ¦Р В РЎвЂР РЋР РЏ.
func Enable(addr string) error {
	k, err := openKey()
	if err != nil {
		return err
	}
	defer k.Close()

	// Р В РЎСџР РЋР вЂљР В Р’ВµР В Р’В¶Р В Р вЂ¦Р В РЎвЂР В Р’Вµ Р В Р’В·Р В Р вЂ¦Р В Р’В°Р РЋРІР‚РЋР В Р’ВµР В Р вЂ¦Р В РЎвЂР РЋР РЏ Р В Р’В·Р В Р’В°Р В РЎвЂ”Р В РЎвЂўР В РЎВР В РЎвЂР В Р вЂ¦Р В Р’В°Р В Р’ВµР В РЎВ Р В РЎвЂўР В РўвЂР В РЎвЂР В Р вЂ¦ Р РЋР вЂљР В Р’В°Р В Р’В·: Р В РЎвЂ”Р В РЎвЂўР В Р вЂ Р РЋРІР‚С™Р В РЎвЂўР РЋР вЂљР В Р вЂ¦Р В РЎвЂўР В Р’Вµ Р В Р вЂ Р В РЎвЂќР В Р’В»Р РЋР вЂ№Р РЋРІР‚РЋР В Р’ВµР В Р вЂ¦Р В РЎвЂР В Р’Вµ Р В Р вЂ¦Р В Р’Вµ Р В РўвЂР В РЎвЂўР В Р’В»Р В Р’В¶Р В Р вЂ¦Р В РЎвЂў
	// Р В Р’В·Р В Р’В°Р РЋРІР‚С™Р В Р’ВµР РЋР вЂљР В Р’ВµР РЋРІР‚С™Р РЋР Р‰ Р В РЎвЂР РЋР С“Р РЋРІР‚В¦Р В РЎвЂўР В РўвЂР В Р вЂ¦Р РЋРІР‚в„–Р В Р’Вµ Р В Р вЂ¦Р В Р’В°Р РЋР С“Р РЋРІР‚С™Р РЋР вЂљР В РЎвЂўР В РІвЂћвЂ“Р В РЎвЂќР В РЎвЂ Р В Р вЂ¦Р В Р’В°Р РЋРІвЂљВ¬Р В РЎвЂР В РЎВР В РЎвЂ Р В Р’В¶Р В Р’Вµ.
	if _, err := readBackup(); err != nil {
		s := &snapshot{}
		if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
			s.Enable = &v
		}
		if v, _, err := k.GetStringValue("ProxyServer"); err == nil {
			s.ProxyServer = &v
		}
		if v, _, err := k.GetStringValue("ProxyOverride"); err == nil {
			s.ProxyOverride = &v
		}
		s.Server = addr
		if err := writeBackup(s); err != nil {
			return err
		}
	}

	if err := k.SetStringValue("ProxyServer", addr); err != nil {
		return err
	}
	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	notify()
	return nil
}

// Disable Р В Р вЂ Р В РЎвЂўР В Р’В·Р В Р вЂ Р РЋР вЂљР В Р’В°Р РЋРІР‚В°Р В Р’В°Р В Р’ВµР РЋРІР‚С™ Р В Р вЂ¦Р В Р’В°Р РЋР С“Р РЋРІР‚С™Р РЋР вЂљР В РЎвЂўР В РІвЂћвЂ“Р В РЎвЂќР В РЎвЂ, Р В РЎвЂќР В РЎвЂўР РЋРІР‚С™Р В РЎвЂўР РЋР вЂљР РЋРІР‚в„–Р В Р’Вµ Р В Р’В±Р РЋРІР‚в„–Р В Р’В»Р В РЎвЂ Р В РўвЂР В РЎвЂў Р В Р вЂ Р В РЎвЂќР В Р’В»Р РЋР вЂ№Р РЋРІР‚РЋР В Р’ВµР В Р вЂ¦Р В РЎвЂР РЋР РЏ.
func Disable() error {
	s, err := readBackup()
	if err != nil {
		return nil
	}
	defer os.Remove(backupPath())

	k, err := openKey()
	if err != nil {
		return err
	}
	defer k.Close()

	restoreDWord(k, "ProxyEnable", s.Enable)
	restoreString(k, "ProxyServer", s.ProxyServer)
	restoreString(k, "ProxyOverride", s.ProxyOverride)
	notify()
	return nil
}

// Enabled Р РЋР С“Р В РЎвЂўР В РЎвЂўР В Р’В±Р РЋРІР‚В°Р В Р’В°Р В Р’ВµР РЋРІР‚С™, Р В Р вЂ Р В РЎвЂќР В Р’В»Р РЋР вЂ№Р РЋРІР‚РЋР РЋРІР‚ВР В Р вЂ¦ Р В Р’В»Р В РЎвЂ Р В РЎвЂ”Р РЋР вЂљР В РЎвЂўР В РЎвЂќР РЋР С“Р В РЎвЂ Р В РЎвЂР В РЎВР В Р’ВµР В Р вЂ¦Р В Р вЂ¦Р В РЎвЂў Р В Р вЂ¦Р В Р’В°Р РЋРІвЂљВ¬Р В Р’ВµР В РІвЂћвЂ“ Р В РЎвЂ”Р РЋР вЂљР В РЎвЂўР В РЎвЂ“Р РЋР вЂљР В Р’В°Р В РЎВР В РЎВР В РЎвЂўР В РІвЂћвЂ“.
func Enabled() bool {
	s, err := readBackup()
	if err != nil {
		return false
	}
	k, err := openKey()
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue("ProxyServer")
	if err != nil || v != s.Server {
		return false
	}
	n, _, err := k.GetIntegerValue("ProxyEnable")
	return err == nil && n == 1
}

// RestoreIfLeftover Р РЋРЎвЂњР В Р’В±Р В РЎвЂР РЋР вЂљР В Р’В°Р В Р’ВµР РЋРІР‚С™ Р В РЎвЂ”Р РЋР вЂљР В РЎвЂўР В РЎвЂќР РЋР С“Р В РЎвЂ, Р В РЎвЂўР РЋР С“Р РЋРІР‚С™Р В Р’В°Р В Р вЂ Р РЋРІвЂљВ¬Р В РЎвЂР В РІвЂћвЂ“Р РЋР С“Р РЋР РЏ Р В РЎвЂ”Р В РЎвЂўР РЋР С“Р В Р’В»Р В Р’Вµ Р В Р’В°Р В Р вЂ Р В Р’В°Р РЋР вЂљР В РЎвЂР В РІвЂћвЂ“Р В Р вЂ¦Р В РЎвЂўР В РЎвЂ“Р В РЎвЂў Р В Р’В·Р В Р’В°Р В Р вЂ Р В Р’ВµР РЋР вЂљР РЋРІвЂљВ¬Р В Р’ВµР В Р вЂ¦Р В РЎвЂР РЋР РЏ.
func RestoreIfLeftover() {
	if _, err := readBackup(); err != nil {
		return
	}
	if Enabled() {
		_ = Disable()
		return
	}
	// Р В РЎСљР В Р’В°Р РЋР С“Р РЋРІР‚С™Р РЋР вЂљР В РЎвЂўР В РІвЂћвЂ“Р В РЎвЂќР В РЎвЂ Р РЋРЎвЂњР В Р’В¶Р В Р’Вµ Р В РўвЂР РЋР вЂљР РЋРЎвЂњР В РЎвЂ“Р В РЎвЂР В Р’Вµ: Р В Р вЂ¦Р В Р’Вµ Р РЋРІР‚С™Р РЋР вЂљР В РЎвЂўР В РЎвЂ“Р В Р’В°Р В Р’ВµР В РЎВ Р В РЎвЂР РЋРІР‚В¦, Р В РЎвЂ”Р РЋР вЂљР В РЎвЂўР РЋР С“Р РЋРІР‚С™Р В РЎвЂў Р В Р’В·Р В Р’В°Р В Р’В±Р РЋРІР‚в„–Р В Р вЂ Р В Р’В°Р В Р’ВµР В РЎВ Р РЋР С“Р В Р вЂ Р В РЎвЂўР В РІвЂћвЂ“ Р РЋРІР‚С›Р В Р’В°Р В РІвЂћвЂ“Р В Р’В».
	_ = os.Remove(backupPath())
}

func restoreDWord(k registry.Key, name string, v *uint64) {
	if v == nil {
		_ = k.DeleteValue(name)
		return
	}
	_ = k.SetDWordValue(name, uint32(*v))
}

func restoreString(k registry.Key, name string, v *string) {
	if v == nil {
		_ = k.DeleteValue(name)
		return
	}
	_ = k.SetStringValue(name, *v)
}

var (
	wininet               = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOption = wininet.NewProc("InternetSetOptionW")
)

const (
	optionRefresh         = 37
	optionSettingsChanged = 39
)

// notify Р РЋР С“Р В РЎвЂўР В РЎвЂўР В Р’В±Р РЋРІР‚В°Р В Р’В°Р В Р’ВµР РЋРІР‚С™ Р В Р’В·Р В Р’В°Р В РЎвЂ”Р РЋРЎвЂњР РЋРІР‚В°Р В Р’ВµР В Р вЂ¦Р В Р вЂ¦Р РЋРІР‚в„–Р В РЎВ Р В РЎвЂ”Р РЋР вЂљР В РЎвЂўР В РЎвЂ“Р РЋР вЂљР В Р’В°Р В РЎВР В РЎВР В Р’В°Р В РЎВ, Р РЋРІР‚РЋР РЋРІР‚С™Р В РЎвЂў Р В Р вЂ¦Р В Р’В°Р РЋР С“Р РЋРІР‚С™Р РЋР вЂљР В РЎвЂўР В РІвЂћвЂ“Р В РЎвЂќР В РЎвЂ Р В РЎвЂ”Р РЋР вЂљР В РЎвЂўР В РЎвЂќР РЋР С“Р В РЎвЂ Р В РЎвЂР В Р’В·Р В РЎВР В Р’ВµР В Р вЂ¦Р В РЎвЂР В Р’В»Р В РЎвЂР РЋР С“Р РЋР Р‰.
func notify() {
	_, _, _ = procInternetSetOption.Call(0, optionSettingsChanged, 0, 0)
	_, _, _ = procInternetSetOption.Call(0, optionRefresh, 0, 0)
}
