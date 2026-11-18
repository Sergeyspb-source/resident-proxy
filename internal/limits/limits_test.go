package limits

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestDomainList(t *testing.T) {
	got := DomainList(" Example.COM, *.company.com;;\n  example.com\t")
	want := []string{"example.com", "company.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DomainList = %v, want %v", got, want)
	}
	if list := DomainList("   , ;  "); len(list) != 0 {
		t.Fatalf("пустой список дал %v", list)
	}
}

func TestNormalize(t *testing.T) {
	v := Normalize(Values{QuotaMB: -5, QuotaMonthMB: -7, RateKBps: -1, Domains: "  "})
	if v.QuotaMB != 0 || v.QuotaMonthMB != 0 || v.RateKBps != 0 || v.Domains != "" {
		t.Fatalf("негативные значения не обнулились: %+v", v)
	}

	v = Normalize(Values{QuotaMB: 2_000_000, QuotaMonthMB: 40_000_000, RateKBps: 2_000_000})
	if v.QuotaMB != 1_000_000 || v.QuotaMonthMB != 30_000_000 || v.RateKBps != 1_000_000 {
		t.Fatalf("верхняя граница не применилась: %+v", v)
	}

	if got := (Values{QuotaMB: 2}).QuotaBytes(); got != 2*1024*1024 {
		t.Fatalf("QuotaBytes = %d", got)
	}
	if got := (Values{QuotaMonthMB: 3}).QuotaMonthBytes(); got != 3*1024*1024 {
		t.Fatalf("QuotaMonthBytes = %d", got)
	}
}

func TestKeyQuota(t *testing.T) {
	k := AccessKey{Limits: Values{QuotaMB: 1}}
	k.Used = 1024*1024 - 1
	if k.OverQuota() {
		t.Fatal("квота не должна считаться исчерпанной")
	}
	k.Used = 1024 * 1024
	if !k.OverQuota() {
		t.Fatal("квота должна считаться исчерпанной")
	}

	m := AccessKey{Limits: Values{QuotaMonthMB: 1}}
	m.UsedMonth = 1024 * 1024
	if !m.OverQuota() {
		t.Fatal("месячная квота не сработала")
	}
}

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-state.json")
	st := State{
		Values: Values{QuotaMB: 10, QuotaMonthMB: 100, RateKBps: 20, Domains: "default.com"},
		Keys: []AccessKey{
			{
				ID:     "1",
				Label:  "Иван",
				Value:  "abc",
				Limits: Values{QuotaMB: 5, Domains: "a.com"},
				Used:   1234,
				Day:    "2026-11-18",
				Month:  "2026-11",
			},
		},
	}
	if err := Save(path, st); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, st) {
		t.Fatalf("Load = %+v, want %+v", got, st)
	}
}
