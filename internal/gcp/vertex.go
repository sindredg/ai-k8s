package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"google.golang.org/api/option"
	htransport "google.golang.org/api/transport/http"

	"github.com/sindredg/ai-k8s/internal/model"
)

// Vertex is a model.Caller on a Vertex AI publisher model. One generateContent call per finding, no
// tools declared, output constrained to the schema. The identity needs aiplatform.endpoints.predict.
type Vertex struct {
	client   *http.Client
	endpoint string
	timeout  time.Duration
}

// NewVertex opens the regional endpoint for one publisher model, authenticated through Workload Identity.
func NewVertex(ctx context.Context, project, location, modelID string, timeout time.Duration) (*Vertex, error) {
	client, _, err := htransport.NewClient(ctx, option.WithScopes("https://www.googleapis.com/auth/cloud-platform"))
	if err != nil {
		return nil, fmt.Errorf("open vertex ai: %w", err)
	}
	endpoint := fmt.Sprintf("https://%s-aiplatform.googleapis.com/v1/projects/%s/locations/%s/publishers/google/models/%s:generateContent",
		location, project, location, modelID)
	return newVertex(client, endpoint, timeout), nil
}

func newVertex(client *http.Client, endpoint string, timeout time.Duration) *Vertex {
	return &Vertex{client: client, endpoint: endpoint, timeout: timeout}
}

type part struct {
	Text         string          `json:"text,omitempty"`
	FunctionCall json.RawMessage `json:"functionCall,omitempty"`
}

type content struct {
	Role  string `json:"role,omitempty"`
	Parts []part `json:"parts"`
}

type generateRequest struct {
	SystemInstruction content          `json:"systemInstruction"`
	Contents          []content        `json:"contents"`
	GenerationConfig  generationConfig `json:"generationConfig"`
}

type generationConfig struct {
	Temperature      float64        `json:"temperature"`
	MaxOutputTokens  int            `json:"maxOutputTokens"`
	ResponseMimeType string         `json:"responseMimeType"`
	ResponseSchema   map[string]any `json:"responseSchema"`
	ThinkingConfig   thinkingConfig `json:"thinkingConfig"`
}

type thinkingConfig struct {
	ThinkingBudget int `json:"thinkingBudget"`
}

type generateResponse struct {
	Candidates []struct {
		Content      content `json:"content"`
		FinishReason string  `json:"finishReason"`
	} `json:"candidates"`
	UsageMetadata struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
		ThoughtsTokenCount   int `json:"thoughtsTokenCount"`
	} `json:"usageMetadata"`
	ModelVersion string `json:"modelVersion"`
}

// Generate makes the call. A non-200 answer or a timeout is an error, which leaves the message
// unacknowledged. A 200 with an empty or odd candidate is a reply, which the settler rejects.
func (v *Vertex) Generate(ctx context.Context, p model.Prompt, params model.Params) (model.Reply, error) {
	body, err := json.Marshal(generateRequest{
		SystemInstruction: content{Parts: []part{{Text: p.System}}},
		Contents:          []content{{Role: "user", Parts: []part{{Text: p.User}}}},
		GenerationConfig: generationConfig{
			Temperature:      params.Temperature,
			MaxOutputTokens:  params.MaxOutputTokens,
			ResponseMimeType: "application/json",
			ResponseSchema:   p.Schema,
			ThinkingConfig:   thinkingConfig{ThinkingBudget: params.ThinkingBudget},
		},
	})
	if err != nil {
		return model.Reply{}, fmt.Errorf("encode the request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint, bytes.NewReader(body))
	if err != nil {
		return model.Reply{}, fmt.Errorf("build the request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return model.Reply{}, fmt.Errorf("generateContent: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return model.Reply{}, fmt.Errorf("read the response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := raw
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return model.Reply{}, fmt.Errorf("generateContent returned %d: %s", resp.StatusCode, msg)
	}

	var out generateResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return model.Reply{}, fmt.Errorf("parse the response: %w", err)
	}

	reply := model.Reply{Usage: model.Usage{
		InputTokens: out.UsageMetadata.PromptTokenCount,
		// Thinking is off, and if it ever runs its tokens bill as output, so they count here.
		OutputTokens: out.UsageMetadata.CandidatesTokenCount + out.UsageMetadata.ThoughtsTokenCount,
		ModelVersion: out.ModelVersion,
	}}
	if len(out.Candidates) == 0 {
		reply.FinishReason = "NO_CANDIDATE"
		return reply, nil
	}
	c := out.Candidates[0]
	reply.FinishReason = c.FinishReason
	for _, pt := range c.Content.Parts {
		if len(pt.FunctionCall) > 0 {
			reply.ToolCalls++
		}
		reply.Text += pt.Text
	}
	return reply, nil
}
