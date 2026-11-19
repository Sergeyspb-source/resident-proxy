// Пакет update проверяет подписанный манифест релиза.
// GPT: добавлено для подписанных обновлений: версия и хеши файлов
// подтверждаются ключом ed25519, приватный ключ хранится вне репозитория.
package update

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	DefaultRepo  = "Sergeyspb-source/resident-proxy"
	ManifestName = "update.json"
	maxManifest  = 64 << 10
)

var (
	ErrSignature = errors.New("подпись релиза неверна")
	ErrVersion   = errors.New("версия в манифесте не совпадает с тегом")
)

type File struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Version   string `json:"version"`
	Files     []File `json:"files"`
	Signature string `json:"signature,omitempty"`
}

func (m *Manifest) payload() ([]byte, error) {
	clean := struct {
		Version string `json:"version"`
		Files   []File `json:"files"`
	}{Version: m.Version, Files: m.Files}
	return json.Marshal(clean)
}

// Sign подписывает манифест приватным ключом ed25519.
func Sign(priv ed25519.PrivateKey, m *Manifest) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("нужен приватный ключ ed25519")
	}
	b, err := m.payload()
	if err != nil {
		return err
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b))
	return nil
}

// Verify проверяет подпись манифеста публичным ключом.
func Verify(pub ed25519.PublicKey, m *Manifest) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("нужен публичный ключ ed25519")
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrSignature
	}
	b, err := m.payload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, b, sig) {
		return ErrSignature
	}
	return nil
}

type Release struct {
	Version  string `json:"version"`
	URL      string `json:"url"`
	Verified bool   `json:"verified"`
	Files    []File `json:"files,omitempty"`
}

// Latest возвращает последний релиз и проверяет его манифест.
// Если манифеста в релизе нет, Verified остаётся false.
func Latest(ctx context.Context, repo string) (*Release, error) {
	if repo == "" {
		repo = DefaultRepo
	}
	cli := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "exitnode-update")

	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: %s", resp.Status)
	}

	var gh struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&gh); err != nil {
		return nil, err
	}

	rel := &Release{Version: strings.TrimPrefix(gh.TagName, "v"), URL: gh.HTMLURL}
	for _, a := range gh.Assets {
		if a.Name != ManifestName {
			continue
		}
		m, err := download(ctx, cli, a.URL)
		if err != nil {
			return rel, err
		}
		if err := Verify(PublicKey, m); err != nil {
			return rel, err
		}
		if m.Version != "" && m.Version != rel.Version {
			return rel, ErrVersion
		}
		rel.Files = m.Files
		rel.Verified = true
		return rel, nil
	}
	return rel, nil
}

func download(ctx context.Context, cli *http.Client, url string) (*Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "exitnode-update")
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest: %s", resp.Status)
	}
	var m Manifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxManifest)).Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}
