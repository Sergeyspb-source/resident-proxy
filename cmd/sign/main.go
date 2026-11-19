// Команда sign готовит ключ и подписанный манифест релиза.
// GPT: служебная утилита для ed25519-подписи обновлений; в поставку не входит.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"exitnode/internal/update"
)

type keyFile struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

func main() {
	var (
		gen     = flag.Bool("gen", false, "создать новую пару ключей")
		keyPath = flag.String("key", "", "файл ключа")
		version = flag.String("version", "", "версия релиза, например 0.0.16")
		dir     = flag.String("dir", "bin", "каталог с файлами релиза")
		files   = flag.String("files", "", "файлы через запятую")
		out     = flag.String("out", "", "куда писать манифест")
	)
	flag.Parse()

	if *keyPath == "" {
		fail("нужен -key")
	}

	if *gen {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fail(err.Error())
		}
		kf := keyFile{
			Private: base64.StdEncoding.EncodeToString(priv),
			Public:  base64.StdEncoding.EncodeToString(pub),
		}
		b, _ := json.MarshalIndent(kf, "", "  ")
		if err := os.WriteFile(*keyPath, b, 0o600); err != nil {
			fail(err.Error())
		}
		fmt.Println("ключ создан:", *keyPath)
		fmt.Println("публичный ключ для internal/update/pubkey.go:")
		fmt.Printf("%#v\n", []byte(pub))
		return
	}

	if *version == "" || *files == "" {
		fail("нужны -version и -files")
	}

	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		fail(err.Error())
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		fail("файл ключа: " + err.Error())
	}
	priv, err := base64.StdEncoding.DecodeString(kf.Private)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		fail("приватный ключ повреждён")
	}

	m := update.Manifest{Version: *version}
	for _, name := range strings.Split(*files, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		path := filepath.Join(*dir, name)
		b, err := os.ReadFile(path)
		if err != nil {
			fail(err.Error())
		}
		sum := sha256.Sum256(b)
		m.Files = append(m.Files, update.File{
			Name:   name,
			Size:   int64(len(b)),
			SHA256: hex.EncodeToString(sum[:]),
		})
	}
	if len(m.Files) == 0 {
		fail("список файлов пуст")
	}

	if err := update.Sign(ed25519.PrivateKey(priv), &m); err != nil {
		fail(err.Error())
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	if *out == "" {
		*out = filepath.Join(*dir, update.ManifestName)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fail(err.Error())
	}
	fmt.Println("манифест:", *out)
	for _, f := range m.Files {
		fmt.Printf("  %s %d %s\n", f.Name, f.Size, f.SHA256[:12])
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
