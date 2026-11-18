// Пакет limits хранит состояние узла: ключи доступа с их лимитами и расходом.
// Настройки переживают перезапуск: файл лежит в приватном каталоге пользователя.
package limits

import (
	"encoding/json"
	"os"
	"strings"
)

// Values — ограничения одного пользователя (ключа).
type Values struct {
	QuotaMB      int64  `json:"quota_mb"`
	QuotaMonthMB int64  `json:"quota_month_mb"`
	RateKBps     int64  `json:"rate_kbps"`
	Domains      string `json:"domains"`
}

// AccessKey — ключ, который владелец узла выдаёт коллеге.
// Хранится целиком, чтобы владелец мог показать его повторно.
type AccessKey struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Value  string `json:"value"`
	Limits Values `json:"limits"`

	Used      int64  `json:"used_bytes"`
	UsedMonth int64  `json:"used_month_bytes"`
	Day       string `json:"day"`
	Month     string `json:"month"`

	QuotaNotified bool `json:"-"`
}

type State struct {
	// Values — значения по умолчанию для новых ключей.
	Values Values      `json:"defaults"`
	Keys   []AccessKey `json:"keys,omitempty"`
}

func Normalize(v Values) Values {
	if v.QuotaMB < 0 {
		v.QuotaMB = 0
	}
	if v.QuotaMB > 1_000_000 {
		v.QuotaMB = 1_000_000
	}
	if v.QuotaMonthMB < 0 {
		v.QuotaMonthMB = 0
	}
	if v.QuotaMonthMB > 30_000_000 {
		v.QuotaMonthMB = 30_000_000
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

func (v Values) QuotaMonthBytes() int64 {
	if v.QuotaMonthMB <= 0 {
		return 0
	}
	return v.QuotaMonthMB * 1024 * 1024
}

func (k *AccessKey) OverQuota() bool {
	q := k.Limits.QuotaBytes()
	qm := k.Limits.QuotaMonthBytes()
	return (q > 0 && k.Used >= q) || (qm > 0 && k.UsedMonth >= qm)
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
	for i := range st.Keys {
		st.Keys[i].Limits = Normalize(st.Keys[i].Limits)
		if st.Keys[i].Used < 0 {
			st.Keys[i].Used = 0
		}
		if st.Keys[i].UsedMonth < 0 {
			st.Keys[i].UsedMonth = 0
		}
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
