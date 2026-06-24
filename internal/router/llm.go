package router

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/shfahiim/cyberai/internal/gemini"
	"github.com/shfahiim/cyberai/internal/llm"
	"github.com/shfahiim/cyberai/internal/project"
)

const llmRouterPolicyVersion = "router-policy-v2"

// LLMRouter calls the configured LLM provider to produce a ScanPlan.
type LLMRouter struct {
	Provider string
	Model    string
	Client   llm.Client
	Cache    *Cache
	Fallback Router
}

func NewLLM(provider, model string, cache *Cache) (*LLMRouter, error) {
	provider = llm.ResolveProvider(provider)
	model = llm.ResolveModel(provider, model)
	client, _, err := llm.NewClient(provider, model, nil)
	if err != nil {
		return nil, err
	}
	return &LLMRouter{
		Provider: provider,
		Model:    model,
		Client:   client,
		Cache:    cache,
		Fallback: NewDefault(),
	}, nil
}

// NewGemini is kept as a compatibility wrapper for existing tests and callers.
func NewGemini(model string, cache *Cache) (*LLMRouter, bool) {
	r, err := NewLLM(gemini.Provider, model, cache)
	if err != nil {
		return &LLMRouter{Provider: gemini.Provider, Model: llm.ResolveModel(gemini.Provider, model), Cache: cache, Fallback: NewDefault()}, false
	}
	return r, r.Client != nil
}

func (g *LLMRouter) Name() string {
	if g.Provider == "" {
		return llm.DefaultProvider
	}
	return g.Provider
}

func (g *LLMRouter) Route(p *project.Profile) (*ScanPlan, error) {
	if p == nil {
		return nil, fmt.Errorf("router: nil profile")
	}

	cacheKey := g.cacheKey(p)
	if g.Cache != nil {
		plan, err := g.Cache.Get(cacheKey)
		if err == nil && plan != nil {
			return plan, nil
		}
	}

	if g.Client == nil {
		plan, _ := g.Fallback.Route(p)
		plan.Reasoning = fmt.Sprintf("no API key configured for provider %s; %s", g.Name(), plan.Reasoning)
		plan.Source = "fallback(" + g.Name() + ")"
		return plan, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	plan, err := g.callLLM(ctx, p)
	if err != nil {
		plan, _ := g.Fallback.Route(p)
		plan.Reasoning = fmt.Sprintf("%s call failed (%s); %s", g.Name(), err, plan.Reasoning)
		plan.Source = "fallback(" + g.Name() + ")"
		return plan, nil
	}

	if g.Cache != nil {
		_ = g.Cache.Put(cacheKey, plan)
	}
	return plan, nil
}

var scanPlanSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"scanners": map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "scanner categories to enable: sast, secrets, sca, iac, license, docker, cicd",
		},
		"semgrep_rulesets": map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "Semgrep rulesets (e.g. p/python, p/security-audit)",
		},
		"gitleaks_config": map[string]any{"type": "string", "description": `"default" or path to custom gitleaks config`},
		"trivy_scanners": map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "trivy --scanners values: vuln, misconfig, license",
		},
		"severity_threshold": map[string]any{
			"type":        "string",
			"enum":        []string{"critical", "high", "medium", "low", "info"},
			"description": "minimum severity to surface",
		},
		"ignore_patterns": map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "additional globs to suppress findings on",
		},
		"reasoning": map[string]any{
			"type":        "string",
			"description": "one-paragraph human explanation of why this plan was chosen",
		},
	},
	"required": []string{"scanners", "severity_threshold", "reasoning"},
}

func (g *LLMRouter) callLLM(ctx context.Context, p *project.Profile) (*ScanPlan, error) {
	profileJSON, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal profile: %w", err)
	}

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

	var plan ScanPlan
	err = g.Client.GenerateStructured(ctx, llm.StructuredRequest{
		SystemInstruction: "You are cyberai's scan router. You choose which security scanners to run against a project. Always return JSON conforming to the provided schema. Never invent scanners that don't exist.",
		Prompt:            userPrompt,
		Temperature:       0,
		Schema:            scanPlanSchema,
	}, &plan)
	if err != nil {
		return nil, err
	}

	plan.ProjectHash = p.Hash()
	plan.Source = g.Name()
	plan.GeneratedAt = time.Now().UTC()
	plan.FromCache = false
	return &plan, nil
}

func (g *LLMRouter) cacheKey(p *project.Profile) string {
	h := sha256.New()
	fmt.Fprintf(h, "profile=%s\n", p.Hash())
	fmt.Fprintf(h, "provider=%s\n", g.Name())
	fmt.Fprintf(h, "model=%s\n", g.Model)
	fmt.Fprintf(h, "policy=%s\n", llmRouterPolicyVersion)
	fmt.Fprintf(h, "total_loc=%d\n", p.TotalLOC)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))[:32]
}
