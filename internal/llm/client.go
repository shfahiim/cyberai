package llm

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/shfahiim/cyberai/internal/gemini"
)

const DefaultProvider = gemini.Provider

type ModelOption struct {
	ID          string
	Label       string
	Status      string
	Description string
}

type StructuredRequest struct {
	SystemInstruction string
	Prompt            string
	Temperature       float64
	Schema            map[string]any
}

type Client interface {
	Provider() string
	Model() string
	GenerateStructured(ctx context.Context, req StructuredRequest, out any) error
}

func ResolveProvider(provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return DefaultProvider
	}
	return provider
}

func ResolveModel(provider, model string) string {
	model = strings.TrimSpace(model)
	p := ResolveProvider(provider)
	if model == "" {
		gcfg, err := LoadGlobalConfig()
		if err == nil {
			if stored, ok := gcfg.Models[p]; ok && stored != "" {
				return stored
			}
		}
	}
	switch p {
	case gemini.Provider:
		return gemini.ResolveModel(model)
	default:
		return model
	}
}

func LookupAPIKey(provider string) (string, string) {
	p := ResolveProvider(provider)
	// 1. Check environment variables (has highest priority)
	switch p {
	case gemini.Provider:
		if key, env := gemini.LookupAPIKey(); key != "" {
			return key, env
		}
	}
	// 2. Check global config
	gcfg, err := LoadGlobalConfig()
	if err == nil {
		if key, ok := gcfg.APIKeys[p]; ok && key != "" {
			return key, "global config"
		}
	}
	return "", ""
}

func PreferredAPIKeyEnv(provider string) string {
	switch ResolveProvider(provider) {
	case gemini.Provider:
		return gemini.EnvGeminiAPIKey
	default:
		return ""
	}
}

func SupportedModels(provider string) []ModelOption {
	switch ResolveProvider(provider) {
	case gemini.Provider:
		models := gemini.SupportedModels()
		out := make([]ModelOption, 0, len(models))
		for _, model := range models {
			out = append(out, ModelOption(model))
		}
		return out
	default:
		return nil
	}
}

func NewClient(provider, model string, httpClient *http.Client) (Client, bool, error) {
	provider = ResolveProvider(provider)
	model = ResolveModel(provider, model)

	switch provider {
	case gemini.Provider:
		key, _ := LookupAPIKey(provider)
		if key == "" {
			return nil, false, nil
		}
		return newGeminiClient(key, model, httpClient), true, nil
	default:
		return nil, false, fmt.Errorf("unsupported llm provider: %s", provider)
	}
}
