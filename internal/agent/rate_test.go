package agent

import (
	"context"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// Проверяет, что лимитер действительно тормозит поток до заданной скорости.
func TestApplyRate(t *testing.T) {
	l := rate.NewLimiter(rate.Inf, 64<<10)
	applyRate(l, 20) // 20 КБ/с, всплеск 64 КБ

	start := time.Now()
	if err := l.WaitN(context.Background(), 64<<10); err != nil {
		t.Fatal(err)
	}
	if err := l.WaitN(context.Background(), 20<<10); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	if elapsed < 500*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("20 КБ при лимите 20 КБ/с ждались %v", elapsed)
	}
}
