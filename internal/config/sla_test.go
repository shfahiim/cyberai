package config

import (
	"testing"
	"time"

	"github.com/shfahiim/cyberai/internal/model"
)

func TestSLAConfig_Deadline(t *testing.T) {
	sla := SLAConfig{Critical: "7d", High: "30d"}
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got := sla.Deadline(model.SeverityCritical, first)
	want := first.Add(7 * 24 * time.Hour)
	if !got.Equal(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseSLADuration(t *testing.T) {
	d, err := ParseSLADuration("90d")
	if err != nil {
		t.Fatal(err)
	}
	if d != 90*24*time.Hour {
		t.Fatalf("got %v", d)
	}
}
