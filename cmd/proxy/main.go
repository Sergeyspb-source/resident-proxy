package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"exitnode/internal/agent"
	"exitnode/internal/buildinfo"
	"exitnode/internal/client"
	"exitnode/internal/clientui"
	"exitnode/internal/desktop"
	"exitnode/internal/hop"
	"exitnode/internal/relay"
	"exitnode/internal/setup"
)

func main() {
	initConsole()
	log.SetFlags(log.Ltime)

	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "relay":
		runRelay(os.Args[2:])
	case "agent":
		runAgent(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	case "hop":
		runHop(os.Args[2:])
	case "setup":
		runSetup(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "неизвестный режим: %s\n\n", os.Args[1])
		usage()
	}
}

func usage() {
	fmt.Print(`exitnode — выход через доверенные компьютеры

  exitnode relay   запуск на VPS2 (шлюз)
  exitnode agent   запуск на ПК коллеги (узел выхода)
  exitnode client  локальный SOCKS5 для того, кто пользуется узлом
  exitnode hop     проброс порта на промежуточном VPS1
  exitnode setup   установка, ярлыки, автозапуск, удаление

Флаги: exitnode relay -h  /  exitnode agent -h  /  exitnode client -h  /  exitnode setup -h
`)
	os.Exit(2)
}

func runRelay(args []string) {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	var cfg relay.Config
	fs.StringVar(&cfg.SocksAddr, "socks", "127.0.0.1:1080", "адрес SOCKS5 (лучше адрес в туннеле до VPS1)")
	fs.StringVar(&cfg.TunnelAddr, "tunnel", ":2053", "адрес, куда подключаются агенты")
	fs.StringVar(&cfg.CertFile, "cert", "", "TLS-сертификат; пусто = без TLS (только для теста)")
	fs.StringVar(&cfg.KeyFile, "key", "", "TLS-ключ")
	fs.StringVar(&cfg.Token, "token", "", "общий токен агентов")
	tokenFile := fs.String("token-file", "", "файл с токеном (вместо -token)")
	fs.BoolVar(&cfg.Dev, "dev", false, "тестовый режим: разрешить работу без TLS")
	fs.BoolVar(&cfg.SocksTLS, "socks-tls", false, "шифровать SOCKS5 тем же сертификатом")
	_ = fs.Parse(args)

	if cfg.Token == "" && *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			log.Fatalf("не прочитать токен: %v", err)
		}
		cfg.Token = strings.TrimSpace(string(b))
	}
	if cfg.Token == "" {
		fmt.Fprintln(os.Stderr, "нужен -token или -token-file")
		os.Exit(2)
	}
	if !cfg.Dev && len(cfg.Token) < 32 {
		fmt.Fprintln(os.Stderr, "токен короче 32 символов; для теста добавьте -dev")
		os.Exit(2)
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		fmt.Fprintln(os.Stderr, "-cert и -key задаются только вместе")
		os.Exit(2)
	}
	if cfg.CertFile == "" && !cfg.Dev {
		fmt.Fprintln(os.Stderr, "без -cert/-key туннель не шифруется; для теста добавьте -dev")
		os.Exit(2)
	}
	if cfg.CertFile == "" {
		log.Println("ВНИМАНИЕ: TLS выключен, это допустимо только в -dev")
	}
	if !cfg.SocksTLS {
		log.Println("ВНИМАНИЕ: SOCKS5 без TLS, это допустимо только в -dev")
	}

	if err := relay.New(cfg, log.Default()).Serve(); err != nil {
		log.Fatal(err)
	}
}

func runAgent(args []string) {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	var cfg agent.Config
	fs.StringVar(&cfg.RelayAddr, "relay", "", "адрес шлюза host:port (обязателен)")
	fs.StringVar(&cfg.Token, "token", "", "токен агента")
	tokenFile := fs.String("token-file", "", "файл с токеном (вместо -token)")
	fs.StringVar(&cfg.Name, "name", "", "имя узла; по умолчанию имя компьютера")
	fs.StringVar(&cfg.UIAddr, "ui", "127.0.0.1:17890", "адрес локальной панели")
	openWindow := true
	fs.BoolVar(&openWindow, "open", true, "открывать окно при запуске")
	fs.BoolVar(&cfg.TrayMode, "tray", false, "запускать только в трее, без окна")
	fs.StringVar(&cfg.PublicSocks, "public-socks", "", "адрес SOCKS для приглашений, например cdn.example.com:2084")
	fs.StringVar(&cfg.AllowPorts, "ports", "80,443", "разрешённые порты через запятую или any")
	fs.Int64Var(&cfg.QuotaMB, "quota-mb", 0, "суточная квота трафика, МБ (0 = без лимита)")
	fs.Int64Var(&cfg.RateKBps, "rate-kbps", 0, "общий лимит скорости, КБ/с (0 = без лимита)")
	fs.StringVar(&cfg.Domains, "allow-domains", "", "разрешённые домены через запятую (пусто = любые)")
	fs.IntVar(&cfg.MaxSessions, "max-sessions", 8, "максимум одновременных подключений")
	configPath := fs.String("config", "", "JSON с relay/token/name/public_socks")
	fs.StringVar(&cfg.ServerName, "server-name", "", "имя сервера в TLS-сертификате")
	fs.BoolVar(&cfg.Insecure, "insecure", false, "не проверять TLS-сертификат (только для теста)")
	fs.BoolVar(&cfg.NoTLS, "plain", false, "без TLS (только для локального теста)")
	_ = fs.Parse(args)

	if *configPath != "" {
		b, err := os.ReadFile(*configPath)
		if err != nil {
			log.Fatalf("конфиг: %v", err)
		}
		var c struct {
			Relay       string `json:"relay"`
			Token       string `json:"token"`
			Name        string `json:"name"`
			PublicSocks string `json:"public_socks"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			log.Fatalf("конфиг: %v", err)
		}
		if cfg.RelayAddr == "" {
			cfg.RelayAddr = c.Relay
		}
		if cfg.Token == "" {
			cfg.Token = c.Token
		}
		if cfg.Name == "" {
			cfg.Name = c.Name
		}
		if cfg.PublicSocks == "" {
			cfg.PublicSocks = c.PublicSocks
		}
	}

	if cfg.Token == "" && *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			log.Fatalf("не прочитать токен: %v", err)
		}
		cfg.Token = strings.TrimSpace(string(b))
	}
	if cfg.RelayAddr == "" || cfg.Token == "" {
		fmt.Fprintln(os.Stderr, "нужны -relay и -token (или -token-file)")
		os.Exit(2)
	}
	cfg.Version = buildinfo.Version
	if cfg.NoTLS {
		log.Println("ВНИМАНИЕ: TLS выключен (только для локального теста)")
	}

	exe, _ := os.Executable()
	if exe != "" {
		logPath := filepath.Join(filepath.Dir(exe), "agent.log")
		if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			log.SetOutput(io.MultiWriter(f, os.Stderr))
		}
	}
	desktop.SetLaunchCommand(exe, os.Args[1:])

	cfg.OnReady = func(url string) {
		if cfg.TrayMode || !openWindow {
			return
		}
		desktop.OpenWindow(url)
	}
	uiURL := "http://" + cfg.UIAddr + "/"

	a, err := agent.New(cfg, log.Default())
	if err != nil {
		log.Printf("не удалось запустить: %v", err)
		return
	}

	go func() {
		if err := a.Run(); err != nil {
			log.Printf("остановлено: %v", err)
			os.Exit(1)
		}
	}()

	if runtime.GOOS != "windows" {
		log.Printf("панель: %s (без трея; остановите процесс для выхода)", uiURL)
		select {}
	}

	desktop.Run(desktop.Hooks{
		URL:      uiURL,
		Title:    "Узел выхода",
		Enabled:  func() bool { return a.Info().Enabled },
		OnToggle: a.SetEnabled,
	})
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	var cfg client.Config
	fs.StringVar(&cfg.Listen, "listen", "127.0.0.1:1080", "локальный адрес SOCKS5 для браузера")
	fs.StringVar(&cfg.Server, "server", "", "адрес шлюза host:port (обязателен)")
	fs.StringVar(&cfg.Key, "key", "", "ключ доступа от владельца узла")
	keyFile := fs.String("key-file", "", "файл с ключом (вместо -key)")
	fs.StringVar(&cfg.User, "user", "", "логин для шлюза (необязательно)")
	fs.BoolVar(&cfg.TLS, "tls", false, "шифровать соединение со шлюзом (нужно для VPS)")
	fs.StringVar(&cfg.ServerName, "server-name", "", "имя в TLS-сертификате шлюза")
	fs.BoolVar(&cfg.Insecure, "insecure", false, "не проверять сертификат (только для теста)")
	fs.BoolVar(&cfg.AllowRemote, "allow-remote", false, "разрешить слушать не только localhost")
	uiMode := fs.Bool("ui", false, "открыть окно клиента")
	invite := fs.String("invite", "", "импортировать приглашение и подключиться")
	trayMode := fs.Bool("tray", false, "открыть только в трее, без окна")
	_ = fs.Parse(args)

	if cfg.Key == "" && *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			log.Fatalf("не прочитать ключ: %v", err)
		}
		cfg.Key = strings.TrimSpace(string(b))
	}

	if *uiMode || *invite != "" || *trayMode || (cfg.Server == "" && cfg.Key == "") {
		runClientGUI(cfg, *invite, *trayMode)
		return
	}

	if cfg.Server == "" || cfg.Key == "" {
		fmt.Fprintln(os.Stderr, "нужны -server и -key (или -key-file)")
		os.Exit(2)
	}
	if err := client.Run(cfg, log.Default()); err != nil {
		log.Fatal(err)
	}
}

func runClientGUI(cfg client.Config, invite string, trayMode bool) {
	path := ""
	if dir, err := os.UserCacheDir(); err == nil {
		_ = os.MkdirAll(filepath.Join(dir, "exitnode"), 0o700)
		path = filepath.Join(dir, "exitnode", "client.json")
	}

	mgr := client.NewManager(log.Default())
	app := clientui.NewApp(mgr, path, log.Default())

	switch {
	case invite != "":
		if err := app.Import(invite); err != nil {
			log.Printf("приглашение: %v", err)
		}
	case cfg.Server != "" && cfg.Key != "":
		_ = app.Connect(cfg.Server, cfg.Key)
	default:
		_ = app.Connect("", "") // сохранённое приглашение
	}

	url := "http://127.0.0.1:17893/"
	onReady := func(u string) {
		log.Printf("окно клиента: %s", u)
		if runtime.GOOS == "windows" && !trayMode {
			desktop.OpenWindow(u)
		}
	}
	go func() {
		if err := clientui.Serve("127.0.0.1:17893", app, log.Default(), onReady); err != nil {
			log.Printf("окно клиента остановлено: %v", err)
			os.Exit(1)
		}
	}()

	if runtime.GOOS != "windows" {
		if !trayMode {
			_ = exec.Command("xdg-open", url).Start()
		}
		log.Printf("клиент работает; остановите Ctrl+C")
		select {}
	}

	desktop.Run(desktop.Hooks{
		URL:         url,
		Title:       "Клиент — Узел выхода",
		Enabled:     app.Running,
		OnToggle:    func(bool) { app.Toggle() },
		ToggleLabel: "Подключено",
	})
}

func runHop(args []string) {
	fs := flag.NewFlagSet("hop", flag.ExitOnError)
	var cfg hop.Config
	fs.StringVar(&cfg.Listen, "listen", "0.0.0.0:2084", "адрес, который слушает VPS1")
	fs.StringVar(&cfg.Target, "target", "", "адрес SOCKS на VPS2 (обязателен)")
	fs.IntVar(&cfg.MaxConns, "max-conns", 512, "максимум одновременных соединений")
	_ = fs.Parse(args)

	if cfg.Target == "" {
		fmt.Fprintln(os.Stderr, "нужен -target, например 31.77.194.253:2084")
		os.Exit(2)
	}
	if err := hop.New(cfg, log.Default()).Serve(); err != nil {
		log.Fatal(err)
	}
}

func runSetup(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	var opts setup.Options
	fs.BoolVar(&opts.Agent, "agent", false, "установить узел выхода")
	fs.BoolVar(&opts.Client, "client", false, "установить клиент")
	fs.StringVar(&opts.Invite, "invite", "", "файл приглашения узла")
	fs.BoolVar(&opts.Uninstall, "uninstall", false, "удалить программу")
	fs.BoolVar(&opts.Systemd, "systemd", false, "Linux: установить systemd-службу")
	fs.BoolVar(&opts.Desktop, "desktop", false, "Linux: ярлык клиента и ассоциация .exitnode")
	fs.StringVar(&opts.Relay, "relay", "", "Linux: адрес шлюза")
	fs.StringVar(&opts.TokenFile, "token-file", "", "Linux: файл с токеном")
	fs.StringVar(&opts.PublicSocks, "public-socks", "", "Linux: адрес SOCKS для приглашений")
	fs.StringVar(&opts.Name, "name", "", "Linux: имя узла")
	_ = fs.Parse(args)

	msg, err := setup.Install(opts)
	if err != nil {
		log.Printf("установка: %v", err)
		setup.Message("Ошибка: " + err.Error())
		return
	}
	log.Printf("установка: %s", msg)
	setup.Message(msg)
	setup.FinishUninstall()
}
