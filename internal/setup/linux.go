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

	"exitnode/internal/traylinux"
)

const unitName = "exitnode.service"

func Install(opts Options) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if opts.Uninstall {
		return uninstallAll(home)
	}
	if !opts.Systemd && !opts.Desktop {
		return "", errors.New("укажите --systemd и/или --desktop")
	}

	bin, err := ensureBinary(home)
	if err != nil {
		return "", err
	}

	var parts []string
	if opts.Desktop {
		if err := installDesktop(home, bin); err != nil {
			return "", err
		}
		parts = append(parts, "Клиент добавлен в меню и связан с .exitnode.")
	}
	if opts.Systemd {
		if err := installSystemdUnit(home, bin, opts); err != nil {
			return "", err
		}
		parts = append(parts, "Узел установлен как служба systemd. Панель: http://127.0.0.1:17890/")
	}
	return strings.Join(parts, " "), nil
}

func FinishUninstall() {}

func Message(text string) { fmt.Println(text) }

func ensureBinary(home string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}
	binPath := filepath.Join(binDir, "exitnode")
	if !sameFile(exe, binPath) {
		if err := copyFile(exe, binPath); err != nil {
			return "", err
		}
		_ = os.Chmod(binPath, 0o755)
	}
	return binPath, nil
}

func installSystemdUnit(home, bin string, opts Options) error {
	relay, token, publicSocks, name := opts.Relay, "", opts.PublicSocks, opts.Name
	if opts.Invite != "" {
		b, err := os.ReadFile(opts.Invite)
		if err != nil {
			return fmt.Errorf("приглашение: %w", err)
		}
		var inv struct {
			Relay       string `json:"relay"`
			Token       string `json:"token"`
			PublicSocks string `json:"public_socks"`
		}
		if err := json.Unmarshal(b, &inv); err != nil || inv.Relay == "" || inv.Token == "" {
			return errors.New("файл не похож на приглашение узла")
		}
		relay, token, publicSocks = inv.Relay, inv.Token, inv.PublicSocks
	}
	if token == "" && opts.TokenFile != "" {
		b, err := os.ReadFile(opts.TokenFile)
		if err != nil {
			return fmt.Errorf("токен: %w", err)
		}
		token = strings.TrimSpace(string(b))
	}
	if relay == "" || token == "" {
		return errors.New("нужны relay и token (или --invite)")
	}

	cfgDir := filepath.Join(home, ".config", "exitnode")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		return err
	}
	cfg, _ := json.MarshalIndent(map[string]string{
		"relay":        relay,
		"token":        token,
		"public_socks": publicSocks,
		"name":         name,
	}, "", "  ")
	cfgPath := filepath.Join(cfgDir, "agent.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		return err
	}

	unitDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return err
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
`, bin, cfgPath)
	if err := os.WriteFile(filepath.Join(unitDir, unitName), []byte(unit), 0o644); err != nil {
		return err
	}

	if out, err := exec.Command("systemctl", "--user", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("systemctl", "--user", "enable", "--now", "exitnode").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if u, err := user.Current(); err == nil {
		_ = exec.Command("loginctl", "enable-linger", u.Username).Run()
	}
	return nil
}

func installDesktop(home, bin string) error {
	apps := filepath.Join(home, ".local", "share", "applications")
	mimeDir := filepath.Join(home, ".local", "share", "mime", "packages")
	if err := os.MkdirAll(apps, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(mimeDir, 0o755); err != nil {
		return err
	}

	// GPT: кладём иконку в тему, чтобы ярлык в меню был не безымянным.
	icons := filepath.Join(home, ".local", "share", "icons", "hicolor", "128x128", "apps")
	if err := os.MkdirAll(icons, 0o755); err != nil {
		return err
	}
	if icon := traylinux.Icon(); len(icon) > 0 {
		if err := os.WriteFile(filepath.Join(icons, "exitnode.png"), icon, 0o644); err != nil {
			return err
		}
	}

	client := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=Exitnode Client
Comment=Локальный SOCKS5 клиент
Exec="%s" client -ui
Icon=exitnode
Terminal=true
Categories=Network;
`, bin)
	if err := os.WriteFile(filepath.Join(apps, "exitnode-client.desktop"), []byte(client), 0o644); err != nil {
		return err
	}

	invite := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=Exitnode Invite
Comment=Открыть приглашение Exitnode
Exec="%s" client -invite %%f
Icon=exitnode
Terminal=true
NoDisplay=true
MimeType=application/x-exitnode;
`, bin)
	if err := os.WriteFile(filepath.Join(apps, "exitnode-invite.desktop"), []byte(invite), 0o644); err != nil {
		return err
	}

	mime := `<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="application/x-exitnode">
    <comment>Exitnode invitation</comment>
    <glob pattern="*.exitnode"/>
  </mime-type>
</mime-info>
`
	if err := os.WriteFile(filepath.Join(mimeDir, "exitnode.xml"), []byte(mime), 0o644); err != nil {
		return err
	}

	_ = exec.Command("update-mime-database", filepath.Join(home, ".local", "share", "mime")).Run()
	_ = exec.Command("update-desktop-database", apps).Run()
	_ = exec.Command("xdg-mime", "default", "exitnode-invite.desktop", "application/x-exitnode").Run()
	return nil
}

func uninstallAll(home string) (string, error) {
	_ = exec.Command("systemctl", "--user", "disable", "--now", "exitnode").Run()
	_ = os.Remove(filepath.Join(home, ".config", "systemd", "user", unitName))
	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	_ = os.Remove(filepath.Join(home, ".config", "exitnode", "agent.json"))

	apps := filepath.Join(home, ".local", "share", "applications")
	_ = os.Remove(filepath.Join(apps, "exitnode-client.desktop"))
	_ = os.Remove(filepath.Join(apps, "exitnode-invite.desktop"))
	_ = os.Remove(filepath.Join(home, ".local", "share", "icons", "hicolor", "128x128", "apps", "exitnode.png"))
	_ = os.Remove(filepath.Join(home, ".local", "share", "mime", "packages", "exitnode.xml"))
	_ = exec.Command("update-mime-database", filepath.Join(home, ".local", "share", "mime")).Run()
	_ = exec.Command("update-desktop-database", apps).Run()
	_ = os.Remove(filepath.Join(home, ".local", "bin", "exitnode"))

	return "Удалено. Ключи и состояние остались в ~/.cache/exitnode.", nil
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
