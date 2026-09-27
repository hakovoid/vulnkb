package extract

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

const sampleHTML = `<!doctype html><html><head>
<title>Fallback title</title>
<meta content="Hacking OpenAI via libheif" property="og:title">
<meta property="article:published_time" content="2026-09-13T08:00:00Z">
<script>var tracking = "CVE-2099-0001";</script>
<style>.x{color:red}</style>
</head><body>
<nav><a href="https://example.com/menu">Menu</a></nav>
<article class="prose">
  <h1>Intro</h1>
  <p>A heap overflow in <b>libheif</b> 1.19.7 &amp; 1.19.8 (CVE-2026-12345) was fixed in 1.23.4, see GHSA-vhm9-85gw-x335.</p>
  <p>See the <a href="https://github.com/strukturag/libheif/releases/tag/v1.23.4">release</a>,
     the <a href="/blog/other">other post</a> and <a href="#fn1">note</a>.</p>
  <!-- commentaire CVE-2099-0002 -->
</article>
<footer>© Hacktron</footer>
</body></html>`

func TestParsePage(t *testing.T) {
	p := ParsePage("https://www.hacktron.ai/blog/hacking-openai", sampleHTML)

	if p.Title != "Hacking OpenAI via libheif" {
		t.Errorf("titre: %q", p.Title)
	}
	if !p.Published.Equal(time.Date(2026, 9, 13, 8, 0, 0, 0, time.UTC)) {
		t.Errorf("date: %v", p.Published)
	}
	for _, want := range []string{"Intro", "libheif 1.19.7 & 1.19.8 (CVE-2026-12345)", "1.23.4"} {
		if !strings.Contains(p.Text, want) {
			t.Errorf("texte sans %q:\n%s", want, p.Text)
		}
	}
	for _, unwanted := range []string{"tracking", "color:red", "Menu", "Hacktron", "CVE-2099"} {
		if strings.Contains(p.Text, unwanted) {
			t.Errorf("texte contient %q:\n%s", unwanted, p.Text)
		}
	}
	want := []string{"https://github.com/strukturag/libheif/releases/tag/v1.23.4"}
	if !reflect.DeepEqual(p.Links, want) {
		t.Errorf("liens: %q", p.Links)
	}
}

type fakeLLM struct {
	reply string
	user  string
}

func (f *fakeLLM) Chat(_ context.Context, _, user string, _ any) (string, error) {
	f.user = user
	return f.reply, nil
}

func TestExtractKeepsOnlyAnchoredFacts(t *testing.T) {
	p := ParsePage("https://www.hacktron.ai/blog/hacking-openai/#top", sampleHTML)
	llm := &fakeLLM{reply: `{
		"title": "Heap overflow dans libheif",
		"summary": "Débordement de tas dans libheif.",
		"component": "libheif",
		"vuln_type": "heap overflow",
		"severity": "Critical",
		"affected_versions": "1.19.7, 1.19.8, 1.20.0",
		"fixed_versions": "1.23.4",
		"remediation": "Mettre à jour libheif en 1.23.4.",
		"ids": ["cve-2026-12345", "CVE-2026-99999", "CVE-2026-12345", "ghsa-VHM9-85gw-x335", "GHSA-aaaa-bbbb-cccc"]
	}`}

	a, err := Extract(context.Background(), llm, p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(llm.user, "libheif 1.19.7") {
		t.Error("le texte de l'article n'a pas été transmis au modèle")
	}

	checks := map[string][2]string{
		"ID":         {a.ID, "article:https://www.hacktron.ai/blog/hacking-openai"},
		"Source":     {a.Source, Source},
		"ExternalID": {a.ExternalID, "CVE-2026-12345, GHSA-vhm9-85gw-x335"}, // identifiants inventés écartés
		"Affected":   {a.AffectedVersions, "1.19.7, 1.19.8"},
		"Fixed":      {a.FixedVersions, "1.23.4"},
		"Severity":   {a.Severity, "Critical"},
	}
	for field, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s: obtenu %q, attendu %q", field, c[0], c[1])
		}
	}
	if len(a.References) != 2 || a.References[0] != p.URL {
		t.Errorf("références: %q", a.References)
	}
}

func TestExtractFallbacks(t *testing.T) {
	p := Page{URL: "https://blog.example/post", Title: "Titre de page", Text: "Aucune CVE ici."}
	a, err := Extract(context.Background(), &fakeLLM{reply: `{"title":"","ids":[]}`}, p)
	if err != nil {
		t.Fatal(err)
	}
	if a.Title != "Titre de page" || a.ExternalID != p.URL {
		t.Errorf("repli titre/ID: %+v", a)
	}

	if _, err := Extract(context.Background(), &fakeLLM{reply: "pas du json"}, p); err == nil {
		t.Error("réponse non JSON acceptée")
	}
	if _, err := Extract(context.Background(), &fakeLLM{}, Page{URL: "x"}); err == nil {
		t.Error("page vide acceptée")
	}
}

func TestOllamaChat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		if req["model"] != "m" || req["stream"] != false || req["format"] == nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"requête inattendue"}`))
			return
		}
		w.Write([]byte(`{"message":{"role":"assistant","content":"{\"title\":\"ok\"}"}}`))
	}))
	defer srv.Close()

	o := &Ollama{Host: srv.URL, Model: "m", NumCtx: 1024, Client: srv.Client()}
	got, err := o.Chat(context.Background(), "sys", "user", schema)
	if err != nil || got != `{"title":"ok"}` {
		t.Fatalf("Chat: %q, %v", got, err)
	}

	o.Model = "autre"
	if _, err := o.Chat(context.Background(), "sys", "user", schema); err == nil || !strings.Contains(err.Error(), "requête inattendue") {
		t.Errorf("erreur Ollama non remontée: %v", err)
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{
		"":                          "http://localhost:11434",
		"0.0.0.0:11434":             "http://localhost:11434",
		"http://192.168.1.5:11434/": "http://192.168.1.5:11434",
	} {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, attendu %q", in, got, want)
		}
	}
}
