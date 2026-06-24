package router

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/shfahiim/cyberai/internal/project"
)

// geminiBaseURL is the public Gemini API endpoint. We hit it directly
// (no SDK) to keep the dependency surface small and to give ourselves
// full control over request shaping.
//
// Docs: https://ai.google.dev/gemini-api/docs/text-generation
const geminiBaseURL = "https://generativelanguage.googleapis.com/v1beta"

// GeminiRouter calls Gemini 2.5 Flash to produce a ScanPlan.
//
// Key design points:
//   - One small call per project (typically < 500 tokens in, < 200 out).
//   - JSON response shape is enforced via response_mime_type=application/json
//   - a response_schema describing ScanPlan.
//   - On any failure (no API key, network, parse, schema mismatch) we
//     fall back to DefaultRouter.Route() and return its plan. The LLM
//     is a "nice to have", never a hard dependency.
//   - Results are cached per project_hash so repeat runs are free.
type GeminiRouter struct {
	APIKey   string
	Model    string // e.g. "gemini-2.5-flash"
	HTTP     *http.Client
	Cache    *Cache // optional; nil disables caching
	Fallback Router // used on failure; defaults to DefaultRouter
}

// NewGemini builds a GeminiRouter. Reads GEMINI_API_KEY from env if
// APIKey is empty. Returns the router and a boolean indicating whether
// the router is "live" (has an API key) or will fall back to default.
//
// Callers should use the default-router fallback if Live() is false.
func NewGemini(model string, cache *Cache) (*GeminiRouter, bool) {
	if model == "" {
		model = "gemini-2.5-flash"
	}
	key := os.Getenv("GEMINI_API_KEY")
	return &GeminiRouter{
		APIKey:   key,
		Model:    model,
		HTTP:     &http.Client{Timeout: 30 * time.Second},
		Cache:    cache,
		Fallback: NewDefault(),
	}, key != ""
}

func (g *GeminiRouter) Name() string { return "gemini" }

// Route returns a plan. Tries cache first, then Gemini, then fallback.
func (g *GeminiRouter) Route(p *project.Profile) (*ScanPlan, error) {
	if p == nil {
		return nil, fmt.Errorf("router: nil profile")
	}

	// 1. Cache hit?
	if g.Cache != nil {
		plan, err := g.Cache.Get(p.Hash())
		if err == nil && plan != nil {
			return plan, nil
		}
	}

	// 2. No API key → fall back.
	if g.APIKey == "" {
		plan, _ := g.Fallback.Route(p)
		plan.Reasoning = "no GEMINI_API_KEY; " + plan.Reasoning
		plan.Source = "fallback(" + g.Name() + ")"
		return plan, nil
	}

	// 3. Call Gemini.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	plan, err := g.callGemini(ctx, p)
	if err != nil {
		// On any error, fall back. The LLM is a "nice to have".
		plan, _ := g.Fallback.Route(p)
		plan.Reasoning = fmt.Sprintf("gemini call failed (%s); %s", err, plan.Reasoning)
		plan.Source = "fallback(" + g.Name() + ")"
		return plan, nil
	}

	// 4. Cache the result.
	if g.Cache != nil {
		_ = g.Cache.Put(plan)
	}
	return plan, nil
}

// --- Gemini REST call ---

// geminiRequest is the request body for generateContent.
// See https://ai.google.dev/api/generate-content
type geminiRequest struct {
	Contents          []geminiContent         `json:"contents"`
	GenerationConfig  *geminiGenerationConfig `json:"generationConfig"`
	SystemInstruction *geminiContent          `json:"systemInstruction,omitempty"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
	Role  string       `json:"role,omitempty"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenerationConfig struct {
	Temperature      float64               `json:"temperature"`
	ResponseMimeType string                `json:"responseMimeType"`
	ResponseSchema   *geminiResponseSchema `json:"responseSchema,omitempty"`
}

type geminiResponseSchema struct {
	Type       string                       `json:"type"`
	Properties map[string]*geminiSchemaProp `json:"properties"`
	Required   []string                     `json:"required"`
}

type geminiSchemaProp struct {
	Type        string            `json:"type"`
	Enum        []string          `json:"enum,omitempty"`
	Description string            `json:"description,omitempty"`
	Items       *geminiSchemaProp `json:"items,omitempty"`
}

// geminiResponse is what the API returns.
type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"error,omitempty"`
}

// scanPlanSchema is the JSON Schema we send to Gemini to constrain its
// output. Property names match the ScanPlan JSON tags.
var scanPlanSchema = &geminiResponseSchema{
	Type: "object",
	Properties: map[string]*geminiSchemaProp{
		"scanners": {
			Type: "array", Items: &geminiSchemaProp{Type: "string"},
			Description: "scanner categories to enable: sast, secrets, sca, iac, license, docker, cicd",
		},
		"semgrep_rulesets": {
			Type: "array", Items: &geminiSchemaProp{Type: "string"},
			Description: "Semgrep rulesets (e.g. p/python, p/security-audit)",
		},
		"gitleaks_config": {Type: "string", Description: `"default" or path to custom gitleaks config`},
		"trivy_scanners": {
			Type: "array", Items: &geminiSchemaProp{Type: "string"},
			Description: "trivy --scanners values: vuln, misconfig, license",
		},
		"severity_threshold": {
			Type: "string", Enum: []string{"critical", "high", "medium", "low", "info"},
			Description: "minimum severity to surface",
		},
		"ignore_patterns": {
			Type: "array", Items: &geminiSchemaProp{Type: "string"},
			Description: "additional globs to suppress findings on",
		},
		"reasoning": {
			Type:        "string",
			Description: "one-paragraph human explanation of why this plan was chosen",
		},
	},
	Required: []string{"scanners", "severity_threshold", "reasoning"},
}

func (g *GeminiRouter) callGemini(ctx context.Context, p *project.Profile) (*ScanPlan, error) {
	profileJSON, _ := json.Marshal(p)
	userPrompt := fmt.Sprintf(`You are a security scanning router for cyberai. Based on the project profile below, decide which scanners and rules to enable.

# Project profile
%s

# Rules
- Only enable scanners that are likely to produce useful findings for this project.
- For Semgrep, pick language-specific rulesets when the project has those languages.
- Default severity threshold is "low" unless the project is large (>=50k LOC) in which case "medium" is more useful.
- Keep the plan minimal: don't enable docker scanning when there's no Dockerfile, don't enable cicd scanning when there are no CI workflows, don't enable license when there are no manifests.
- Reasoning MUST be one paragraph and explain the tradeoffs.

Return JSON matching the responseSchema.`, string(profileJSON))

	body := geminiRequest{
		SystemInstruction: &geminiContent{Parts: []geminiPart{{
			Text: "You are cyberai's scan router. You choose which security scanners to run against a project. Always return JSON conforming to the provided schema. Never invent scanners that don't exist.",
		}}},
		Contents: []geminiContent{{
			Role:  "user",
			Parts: []geminiPart{{Text: userPrompt}},
		}},
		GenerationConfig: &geminiGenerationConfig{
			Temperature:      0,
			ResponseMimeType: "application/json",
			ResponseSchema:   scanPlanSchema,
		},
	}

	bodyJSON, _ := json.Marshal(body)
	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s", geminiBaseURL, g.Model, g.APIKey)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, truncate(string(data), 200))
	}

	var gr geminiResponse
	if err := json.Unmarshal(data, &gr); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if gr.Error != nil {
		return nil, fmt.Errorf("api: %s", gr.Error.Message)
	}
	if len(gr.Candidates) == 0 || len(gr.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("empty response")
	}

	// Parse the inner JSON (Gemini's structured output gives us a string
	// that's already valid JSON matching the schema).
	var plan ScanPlan
	text := gr.Candidates[0].Content.Parts[0].Text
	if err := json.Unmarshal([]byte(text), &plan); err != nil {
		return nil, fmt.Errorf("parse plan: %w (text: %s)", err, truncate(text, 200))
	}
	plan.ProjectHash = p.Hash()
	plan.Source = "gemini"
	plan.GeneratedAt = time.Now().UTC()
	plan.FromCache = false
	return &plan, nil
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
