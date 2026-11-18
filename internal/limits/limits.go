// Пакет limits хранит ограничения узла и израсходованный трафик.
// Настройки переживают перезапуск: файл лежит рядом с исполняемым файлом.
package limits

import (
	"encoding/json"
	"os"
	"strings"
)

type Values struct {
	QuotaMB  int64  `json:"quota_mb"`
	RateKBps int64  `json:"rate_kbps"`
	Domains  string `json:"domains"`
}

type State struct {
	Values
	Used int64  `json:"used_bytes"`
	Day  string `json:"day"`
}

func Normalize(v Values) Values {
	if v.QuotaMB < 0 {
		v.QuotaMB = 0
	}
	if v.QuotaMB > 1_000_000 {
		v.QuotaMB = 1_000_000
	}
	if v.RateKBps < 0 {
		v.RateKBps = 0
	}
	if v.RateKBps > 1_000_000 {
		v.RateKBps = 1_000_000
	}
	v.Domains = strings.TrimSpace(v.Domains)
	return v
}

func (v Values) QuotaBytes() int64 {
	if v.QuotaMB <= 0 {
		return 0
	}
	return v.QuotaMB * 1024 * 1024
}

// DomainList нормализует список: нижний регистр, без "*." и точек по краям.
// Пустой результат означает "разрешено всё".
func DomainList(s string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, part := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	}) {
		d := strings.ToLower(strings.TrimSpace(part))
		d = strings.TrimPrefix(d, "*.")
		d = strings.Trim(d, ".")
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

func Load(path string) (State, error) {
	var st State
	b, err := os.ReadFile(path)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, err
	}
	st.Values = Normalize(st.Values)
	if st.Used < 0 {
		st.Used = 0
	}
	return st, nil
}

func Save(path string, st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
