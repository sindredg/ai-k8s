package gcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sindredg/ai-k8s/internal/model"
)

func TestTheRequestAsksForDeterministicSchemaBoundOutputWithNoThinking(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = io.WriteString(w, `{"candidates":[{"content":{"parts":[{"text":"{\"verdict\":\"new\"}"}]},"finishReason":"STOP"}],
			"usageMetadata":{"promptTokenCount":9000,"candidatesTokenCount":100,"thoughtsTokenCount":20},"modelVersion":"gemini-2.5-flash-001"}`)
	}))
	defer srv.Close()

	v := newVertex(srv.Client(), srv.URL, time.Second)
	reply, err := v.Generate(context.Background(),
		model.Prompt{System: "sys", User: "usr", Schema: map[string]any{"type": "OBJECT"}},
		model.Params{Model: "m", MaxOutputTokens: 1024})
	if err != nil {
		t.Fatal(err)
	}

	cfg := got["generationConfig"].(map[string]any)
	if cfg["temperature"].(float64) != 0 || cfg["maxOutputTokens"].(float64) != 1024 || cfg["responseMimeType"] != "application/json" {
		t.Fatalf("generation config: %v", cfg)
	}
	if cfg["responseSchema"] == nil || cfg["thinkingConfig"].(map[string]any)["thinkingBudget"].(float64) != 0 {
		t.Fatalf("schema or thinking budget missing: %v", cfg)
	}
	if _, declared := got["tools"]; declared {
		t.Fatal("tools were declared, and the tool budget is zero")
	}
	if reply.FinishReason != "STOP" || reply.Text != `{"verdict":"new"}` {
		t.Fatalf("reply: %+v", reply)
	}
	if reply.Usage.InputTokens != 9000 || reply.Usage.OutputTokens != 120 {
		t.Fatalf("thinking tokens must bill as output: %+v", reply.Usage)
	}
}

func TestAFunctionCallIsCounted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"candidates":[{"content":{"parts":[{"functionCall":{"name":"x"}}]},"finishReason":"STOP"}]}`)
	}))
	defer srv.Close()

	reply, err := newVertex(srv.Client(), srv.URL, time.Second).Generate(context.Background(), model.Prompt{}, model.Params{})
	if err != nil || reply.ToolCalls != 1 {
		t.Fatalf("tool calls %d, err %v", reply.ToolCalls, err)
	}
}

func TestARefusedPermissionIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":{"code":403,"status":"PERMISSION_DENIED"}}`)
	}))
	defer srv.Close()

	_, err := newVertex(srv.Client(), srv.URL, time.Second).Generate(context.Background(), model.Prompt{}, model.Params{})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("got %v", err)
	}
}

func TestASlowModelTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	start := time.Now()
	_, err := newVertex(srv.Client(), srv.URL, 50*time.Millisecond).Generate(context.Background(), model.Prompt{}, model.Params{})
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("got %v after %s", err, time.Since(start))
	}
}
