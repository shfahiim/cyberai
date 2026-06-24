package llm

import (
	"testing"

	"github.com/shfahiim/cyberai/internal/gemini"
)

func TestResolveProvider_Default(t *testing.T) {
	if got := ResolveProvider(""); got != DefaultProvider {
		t.Fatalf("ResolveProvider(\"\") = %q, want %q", got, DefaultProvider)
	}
}

func TestResolveModel_UsesProviderDefault(t *testing.T) {
	if got := ResolveModel(gemini.Provider, ""); got != gemini.DefaultModel {
		t.Fatalf("ResolveModel default = %q, want %q", got, gemini.DefaultModel)
	}
}

func TestLookupAPIKey_UsesProviderLookup(t *testing.T) {
	t.Setenv(gemini.EnvGeminiAPIKey, "gemini-key")
	t.Setenv(gemini.EnvGoogleAPIKey, "")
	key, source := LookupAPIKey(gemini.Provider)
	if key != "gemini-key" || source != gemini.EnvGeminiAPIKey {
		t.Fatalf("LookupAPIKey = (%q, %q)", key, source)
	}
}

func TestNewClient_UnsupportedProvider(t *testing.T) {
	if _, _, err := NewClient("unknown", "x", nil); err == nil {
		t.Fatal("expected error for unsupported provider")
	}
}
