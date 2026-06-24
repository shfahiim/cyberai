package gemini

import (
	"os"
	"strings"
)

const (
	Provider        = "gemini"
	EnvGoogleAPIKey = "GOOGLE_API_KEY"
	EnvGeminiAPIKey = "GEMINI_API_KEY"
	DefaultModel    = "gemini-3.5-flash"
)

type ModelOption struct {
	ID          string
	Label       string
	Status      string
	Description string
}

var supportedModels = []ModelOption{
	{
		ID:          "gemini-3.5-flash",
		Label:       "Gemini 3.5 Flash",
		Status:      "stable",
		Description: "Most intelligent Flash model for agentic and coding tasks.",
	},
	{
		ID:          "gemini-3.1-pro-preview",
		Label:       "Gemini 3.1 Pro",
		Status:      "preview",
		Description: "Advanced reasoning and coding model for harder problems.",
	},
	{
		ID:          "gemini-3-flash-preview",
		Label:       "Gemini 3 Flash",
		Status:      "preview",
		Description: "Frontier-class Flash preview with strong multimodal support.",
	},
	{
		ID:          "gemini-3.1-flash-lite",
		Label:       "Gemini 3.1 Flash-Lite",
		Status:      "stable",
		Description: "Lower-latency, lower-cost model for high-volume workloads.",
	},
}

func LookupAPIKey() (string, string) {
	if key := strings.TrimSpace(os.Getenv(EnvGoogleAPIKey)); key != "" {
		return key, EnvGoogleAPIKey
	}
	if key := strings.TrimSpace(os.Getenv(EnvGeminiAPIKey)); key != "" {
		return key, EnvGeminiAPIKey
	}
	return "", ""
}

func ResolveModel(model string) string {
	model = strings.TrimSpace(model)
	if model == "" {
		return DefaultModel
	}
	return model
}

func SupportedModels() []ModelOption {
	out := make([]ModelOption, len(supportedModels))
	copy(out, supportedModels)
	return out
}
