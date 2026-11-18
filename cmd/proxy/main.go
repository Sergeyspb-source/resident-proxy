package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"exitnode/internal/agent"
	"exitnode/internal/client"
	"exitnode/internal/desktop"
	"exitnode/internal/relay"
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

Флаги: exitnode relay -h  /  exitnode agent -h  /  exitnode client -h
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
	fs.StringVar(&cfg.AllowPorts, "ports", "80,443", "разрешённые порты через запятую или any")
	fs.Int64Var(&cfg.QuotaMB, "quota-mb", 0, "суточная квота трафика, МБ (0 = без лимита)")
	fs.Int64Var(&cfg.RateKBps, "rate-kbps", 0, "общий лимит скорости, КБ/с (0 = без лимита)")
	fs.StringVar(&cfg.Domains, "allow-domains", "", "разрешённые домены через запятую (пусто = любые)")
	fs.IntVar(&cfg.MaxSessions, "max-sessions", 8, "максимум одновременных подключений")
	fs.StringVar(&cfg.ServerName, "server-name", "", "имя сервера в TLS-сертификате")
	fs.BoolVar(&cfg.Insecure, "insecure", false, "не проверять TLS-сертификат (только для теста)")
	fs.BoolVar(&cfg.NoTLS, "plain", false, "без TLS (только для локального теста)")
	_ = fs.Parse(args)

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

	desktop.Run(desktop.Hooks{
		URL:      uiURL,
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
	_ = fs.Parse(args)

	if cfg.Key == "" && *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			log.Fatalf("не прочитать ключ: %v", err)
		}
		cfg.Key = strings.TrimSpace(string(b))
	}
	if cfg.Server == "" || cfg.Key == "" {
		fmt.Fprintln(os.Stderr, "нужны -server и -key (или -key-file)")
		os.Exit(2)
	}
	if err := client.Run(cfg, log.Default()); err != nil {
		log.Fatal(err)
	}
}
