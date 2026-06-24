package gemini

import "testing"

func TestLookupAPIKey_PrefersGoogleAPIKey(t *testing.T) {
	t.Setenv(EnvGeminiAPIKey, "gemini-key")
	t.Setenv(EnvGoogleAPIKey, "google-key")

	key, source := LookupAPIKey()
	if key != "google-key" {
		t.Fatalf("key = %q, want google-key", key)
	}
	if source != EnvGoogleAPIKey {
		t.Fatalf("source = %q, want %q", source, EnvGoogleAPIKey)
	}
}

func TestLookupAPIKey_FallsBackToGeminiAPIKey(t *testing.T) {
	t.Setenv(EnvGeminiAPIKey, "gemini-key")
	t.Setenv(EnvGoogleAPIKey, "")

	key, source := LookupAPIKey()
	if key != "gemini-key" {
		t.Fatalf("key = %q, want gemini-key", key)
	}
	if source != EnvGeminiAPIKey {
		t.Fatalf("source = %q, want %q", source, EnvGeminiAPIKey)
	}
}

func TestResolveModel_Default(t *testing.T) {
	if got := ResolveModel(""); got != DefaultModel {
		t.Fatalf("ResolveModel(\"\") = %q, want %q", got, DefaultModel)
	}
}

func TestSupportedModels_ContainsDefault(t *testing.T) {
	models := SupportedModels()
	for _, model := range models {
		if model.ID == DefaultModel {
			return
		}
	}
	t.Fatalf("default model %q not found in supported models", DefaultModel)
}
