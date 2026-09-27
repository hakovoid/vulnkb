package extract

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"syscall"
)

// LLM est le contrat minimal attendu du modèle : une réponse JSON conforme
// au schéma fourni.
type LLM interface {
	Chat(ctx context.Context, system, user string, schema any) (string, error)
}

// Ollama appelle l'API /api/chat d'une instance Ollama.
type Ollama struct {
	Host   string // ex. http://localhost:11434
	Model  string
	NumCtx int
	Client *http.Client
}

// NormalizeHost accepte aussi la forme "hôte:port" de la variable OLLAMA_HOST.
func NormalizeHost(h string) string {
	h = strings.TrimRight(strings.TrimSpace(h), "/")
	if h == "" {
		return "http://localhost:11434"
	}
	if !strings.Contains(h, "://") {
		h = "http://" + h
	}
	return strings.Replace(h, "://0.0.0.0", "://localhost", 1)
}

func (o *Ollama) Chat(ctx context.Context, system, user string, schema any) (string, error) {
	payload := map[string]any{
		"model":  o.Model,
		"stream": false,
		"format": schema,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"options": map[string]any{"temperature": 0, "num_ctx": o.NumCtx},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.Host+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.Client.Do(req)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return "", fmt.Errorf("Ollama injoignable sur %s (lancer : cd ~/kuro_apps/ollama && docker compose up -d)", o.Host)
		}
		return "", fmt.Errorf("appel Ollama: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(raw))
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return "", fmt.Errorf("Ollama (%s): statut %d: %s", o.Model, resp.StatusCode, msg)
	}
	var out struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("réponse Ollama illisible: %w", err)
	}
	return out.Message.Content, nil
}
