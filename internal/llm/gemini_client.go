package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const geminiBaseURL = "https://generativelanguage.googleapis.com/v1beta"

type geminiClient struct {
	apiKey string
	model  string
	http   *http.Client
}

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
	Temperature      float64        `json:"temperature"`
	ResponseMimeType string         `json:"responseMimeType"`
	ResponseSchema   map[string]any `json:"responseSchema,omitempty"`
}

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

func newGeminiClient(apiKey, model string, httpClient *http.Client) Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &geminiClient{apiKey: apiKey, model: model, http: httpClient}
}

func (g *geminiClient) Provider() string { return DefaultProvider }

func (g *geminiClient) Model() string { return g.model }

func (g *geminiClient) GenerateStructured(ctx context.Context, req StructuredRequest, out any) error {
	body := geminiRequest{
		SystemInstruction: &geminiContent{Parts: []geminiPart{{Text: req.SystemInstruction}}},
		Contents: []geminiContent{{
			Role:  "user",
			Parts: []geminiPart{{Text: req.Prompt}},
		}},
		GenerationConfig: &geminiGenerationConfig{
			Temperature:      req.Temperature,
			ResponseMimeType: "application/json",
			ResponseSchema:   req.Schema,
		},
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s", geminiBaseURL, g.model, g.apiKey)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := g.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %s", resp.StatusCode, truncate(string(data), 200))
	}

	var parsed geminiResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}
	if parsed.Error != nil {
		return fmt.Errorf("api: %s", parsed.Error.Message)
	}
	if len(parsed.Candidates) == 0 || len(parsed.Candidates[0].Content.Parts) == 0 {
		return fmt.Errorf("empty response")
	}

	if err := json.Unmarshal([]byte(parsed.Candidates[0].Content.Parts[0].Text), out); err != nil {
		return fmt.Errorf("parse structured output: %w", err)
	}
	return nil
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
