package agent

import "testing"

func TestGuardDomains(t *testing.T) {
	g, err := NewGuard("443")
	if err != nil {
		t.Fatal(err)
	}
	if !g.allowedHost("", "anything.example") {
		t.Fatal("пустой список должен разрешать любой домен")
	}

	spec := "example.com, *.company.com, 203.0.113.7"
	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"www.example.com", true},
		{"EXAMPLE.COM", true},
		{"example.com.", true},
		{"badexample.com", false},
		{"company.com", true},
		{"api.company.com", true},
		{"other.com", false},
		{"203.0.113.7", true},
		{"203.0.113.8", false},
	}
	for _, c := range cases {
		if got := g.allowedHost(spec, c.host); got != c.want {
			t.Errorf("allowedHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestGuardPorts(t *testing.T) {
	g, err := NewGuard("80,443")
	if err != nil {
		t.Fatal(err)
	}
	if !g.allowed(443) || !g.allowed(80) {
		t.Fatal("разрешённые порты отклонены")
	}
	if g.allowed(22) {
		t.Fatal("порт 22 не должен быть разрешён")
	}
}
