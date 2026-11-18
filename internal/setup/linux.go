//go:build linux

package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

const unitName = "exitnode.service"

// Install на Linux ставит systemd-юнит пользователя.
func Install(opts Options) (string, error) {
	if !opts.Systemd {
		return "", errors.New("для Linux используйте: setup --systemd (или --uninstall)")
	}
	return installSystemd(opts)
}

func FinishUninstall() {}

func Message(text string) { fmt.Println(text) }

func installSystemd(opts Options) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	unitPath := filepath.Join(unitDir, unitName)
	cfgDir := filepath.Join(home, ".config", "exitnode")
	cfgPath := filepath.Join(cfgDir, "agent.json")

	if opts.Uninstall {
		_ = exec.Command("systemctl", "--user", "disable", "--now", "exitnode").Run()
		_ = os.Remove(unitPath)
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
		_ = os.Remove(cfgPath)
		return "Служба удалена. Ключи и состояние остались в ~/.cache/exitnode.", nil
	}

	relay, token, publicSocks, name := opts.Relay, "", opts.PublicSocks, opts.Name
	if opts.Invite != "" {
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
		relay, token, publicSocks = inv.Relay, inv.Token, inv.PublicSocks
	}
	if token == "" && opts.TokenFile != "" {
		b, err := os.ReadFile(opts.TokenFile)
		if err != nil {
			return "", fmt.Errorf("токен: %w", err)
		}
		token = strings.TrimSpace(string(b))
	}
	if relay == "" || token == "" {
		return "", errors.New("нужны relay и token (или --invite)")
	}

	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	binDir := filepath.Join(home, ".local", "bin")
	binPath := filepath.Join(binDir, "exitnode")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}
	if !sameFile(exe, binPath) {
		if err := copyFile(exe, binPath); err != nil {
			return "", err
		}
		_ = os.Chmod(binPath, 0o755)
	}

	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		return "", err
	}
	cfg, _ := json.MarshalIndent(map[string]string{
		"relay":        relay,
		"token":        token,
		"public_socks": publicSocks,
		"name":         name,
	}, "", "  ")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		return "", err
	}

	unit := fmt.Sprintf(`[Unit]
Description=exitnode agent
After=network-online.target

[Service]
ExecStart=%s agent -config %s -ui 127.0.0.1:17890
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
`, binPath, cfgPath)
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return "", err
	}

	if out, err := exec.Command("systemctl", "--user", "daemon-reload").CombinedOutput(); err != nil {
		return "", fmt.Errorf("systemctl: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("systemctl", "--user", "enable", "--now", "exitnode").CombinedOutput(); err != nil {
		return "", fmt.Errorf("systemctl: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	if u, err := user.Current(); err == nil {
		_ = exec.Command("loginctl", "enable-linger", u.Username).Run()
	}

	return "Узел установлен как служба systemd. Панель: http://127.0.0.1:17890/", nil
}

func sameFile(a, b string) bool {
	ia, err1 := os.Stat(a)
	ib, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(ia, ib)
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o755)
}
