package setup

// Options — что именно устанавливаем.
type Options struct {
	Agent       bool
	Client      bool
	Uninstall   bool
	Systemd     bool
	Desktop     bool
	Invite      string
	Relay       string
	TokenFile   string
	PublicSocks string
	Name        string
}
