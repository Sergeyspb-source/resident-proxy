package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"exitnode/internal/agent"
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

Флаги: exitnode relay -h  /  exitnode agent -h
`)
	os.Exit(2)
}

func runRelay(args []string) {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	var cfg relay.Config
	fs.StringVar(&cfg.SocksAddr, "socks", "127.0.0.1:1080", "адрес SOCKS5 (лучше адрес в туннеле до VPS1)")
	fs.StringVar(&cfg.TunnelAddr, "tunnel", ":8443", "адрес, куда подключаются агенты")
	fs.StringVar(&cfg.CertFile, "cert", "", "TLS-сертификат; пусто = без TLS (только для теста)")
	fs.StringVar(&cfg.KeyFile, "key", "", "TLS-ключ")
	fs.StringVar(&cfg.Token, "token", "", "общий токен агентов (обязателен)")
	fs.StringVar(&cfg.SocksUser, "socks-user", "", "логин SOCKS5; пусто = без пароля")
	fs.StringVar(&cfg.SocksPass, "socks-pass", "", "пароль SOCKS5")
	_ = fs.Parse(args)

	if cfg.Token == "" {
		fmt.Fprintln(os.Stderr, "нужен -token")
		os.Exit(2)
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		fmt.Fprintln(os.Stderr, "-cert и -key задаются только вместе")
		os.Exit(2)
	}
	if cfg.CertFile == "" {
		log.Println("ВНИМАНИЕ: TLS выключен, туннель до агента не шифруется (только для локального теста)")
	}

	if err := relay.New(cfg, log.Default()).Serve(); err != nil {
		log.Fatal(err)
	}
}

func runAgent(args []string) {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	var cfg agent.Config
	fs.StringVar(&cfg.RelayAddr, "relay", "", "адрес шлюза host:port (обязателен)")
	fs.StringVar(&cfg.Token, "token", "", "токен агента (обязателен)")
	fs.StringVar(&cfg.Name, "name", "", "имя узла; по умолчанию имя компьютера")
	fs.StringVar(&cfg.UIAddr, "ui", "127.0.0.1:17890", "адрес локальной панели")
	fs.BoolVar(&cfg.OpenBrowser, "open", true, "открыть панель в браузере при запуске")
	fs.StringVar(&cfg.AllowPorts, "ports", "80,443", "разрешённые порты через запятую или any")
	fs.IntVar(&cfg.MaxSessions, "max-sessions", 8, "максимум одновременных подключений")
	fs.StringVar(&cfg.ServerName, "server-name", "", "имя сервера в TLS-сертификате")
	fs.BoolVar(&cfg.Insecure, "insecure", false, "не проверять TLS-сертификат (только для теста)")
	fs.BoolVar(&cfg.NoTLS, "plain", false, "без TLS (только для локального теста)")
	_ = fs.Parse(args)

	if cfg.RelayAddr == "" || cfg.Token == "" {
		fmt.Fprintln(os.Stderr, "нужны -relay и -token")
		os.Exit(2)
	}
	if cfg.NoTLS {
		log.Println("ВНИМАНИЕ: TLS выключен (только для локального теста)")
	}

	a, err := agent.New(cfg, log.Default())
	if err != nil {
		log.Fatal(err)
	}
	if err := a.Run(); err != nil {
		log.Fatal(err)
	}
}
