package extract

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"vulnkb/internal/model"
)

// Source est la valeur de model.Advisory.Source pour les fiches extraites :
// elle signale dans la TUI que le contenu vient d'un LLM et doit être vérifié.
const Source = "article-ia"

// MaxTextChars borne le texte envoyé au modèle (~8 000 tokens).
const MaxTextChars = 30000

// Fields est la fiche que le modèle doit renvoyer.
type Fields struct {
	Title            string   `json:"title"`
	Summary          string   `json:"summary"`
	Component        string   `json:"component"`
	VulnType         string   `json:"vuln_type"`
	Severity         string   `json:"severity"`
	AffectedVersions string   `json:"affected_versions"`
	FixedVersions    string   `json:"fixed_versions"`
	Remediation      string   `json:"remediation"`
	IDs              []string `json:"ids"`
}

var schema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"title":             map[string]any{"type": "string"},
		"summary":           map[string]any{"type": "string"},
		"component":         map[string]any{"type": "string"},
		"vuln_type":         map[string]any{"type": "string"},
		"severity":          map[string]any{"type": "string", "enum": []string{"Critical", "High", "Medium", "Low", ""}},
		"affected_versions": map[string]any{"type": "string"},
		"fixed_versions":    map[string]any{"type": "string"},
		"remediation":       map[string]any{"type": "string"},
		"ids":               map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	},
	"required": []string{"title", "summary", "component", "vuln_type", "severity",
		"affected_versions", "fixed_versions", "remediation", "ids"},
}

const systemPrompt = `Tu es analyste en sécurité informatique. On te donne un article technique (write-up, billet de blog, advisory). Tu en tires une fiche de vulnérabilité au format JSON.

Règles strictes :
- N'invente rien. Si une information n'est pas écrite dans l'article, mets "" (ou [] pour ids).
- Recopie les numéros de version et les identifiants exactement comme dans l'article.
- Rédige title, summary et remediation en français, même si l'article est en anglais.

Champs :
- title : titre court de la faille (100 caractères maximum).
- summary : 3 à 6 phrases : ce qui est vulnérable, comment c'est exploité, l'impact.
- component : logiciel(s) ou bibliothèque(s) vulnérable(s), séparés par des virgules.
- vuln_type : type(s) de faille (ex. heap overflow, RCE, SSRF, account takeover).
- severity : Critical, High, Medium ou Low selon l'impact décrit ; "" si l'article ne permet pas de juger.
- affected_versions : versions vulnérables citées.
- fixed_versions : versions qui corrigent la faille (souvent « corrigé dans », « patched in », « latest security release »).
- remediation : action concrète recommandée (mise à jour, configuration…).
- ids : identifiants CVE (CVE-AAAA-NNNN) et GitHub (GHSA-xxxx-xxxx-xxxx) cités dans l'article.`

const userSuffix = "\n\n---\nProduis la fiche JSON. Rappel : title, summary et remediation en français ; n'invente ni version ni identifiant."

var (
	idRe      = regexp.MustCompile(`(?i)\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[a-z0-9]{4}){3})\b`)
	versionRe = regexp.MustCompile(`\d+(?:\.\d+)+`)
)

// ContextFor estime la fenêtre de contexte (en tokens) nécessaire pour un
// texte, invite et réponse comprises.
func ContextFor(text string) int {
	n := min(len([]rune(text)), MaxTextChars)/3 + 2048
	n = (n + 1023) / 1024 * 1024
	return max(4096, min(n, 16384))
}

// Extract demande au modèle une fiche pour la page, puis écarte ce qui n'est
// pas ancré dans le texte (CVE ou numéros de version absents de l'article).
func Extract(ctx context.Context, llm LLM, p Page) (model.Advisory, error) {
	text := p.Text
	if r := []rune(text); len(r) > MaxTextChars {
		text = string(r[:MaxTextChars])
	}
	if strings.TrimSpace(text) == "" {
		return model.Advisory{}, fmt.Errorf("aucun texte exploitable dans %s", p.URL)
	}

	user := fmt.Sprintf("URL : %s\nTitre de la page : %s\n\nArticle :\n%s%s", p.URL, p.Title, text, userSuffix)
	raw, err := llm.Chat(ctx, systemPrompt, user, schema)
	if err != nil {
		return model.Advisory{}, err
	}
	var f Fields
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		return model.Advisory{}, fmt.Errorf("réponse du modèle non conforme: %w", err)
	}
	return toAdvisory(p, f), nil
}

func toAdvisory(p Page, f Fields) model.Advisory {
	ids := anchoredIDs(f.IDs, p.Text)

	title := strings.TrimSpace(f.Title)
	if title == "" {
		title = p.Title
	}
	externalID := strings.Join(ids, ", ")
	if externalID == "" {
		externalID = p.URL
	}

	return model.Advisory{
		ID:               "article:" + canonicalURL(p.URL),
		Source:           Source,
		ExternalID:       externalID,
		Title:            title,
		Summary:          strings.TrimSpace(f.Summary),
		Component:        strings.TrimSpace(f.Component),
		VulnType:         strings.TrimSpace(f.VulnType),
		Severity:         strings.TrimSpace(f.Severity),
		AffectedVersions: anchoredVersions(f.AffectedVersions, p.Text),
		FixedVersions:    anchoredVersions(f.FixedVersions, p.Text),
		Remediation:      strings.TrimSpace(f.Remediation),
		References:       append([]string{p.URL}, p.Links...),
		Published:        p.Published,
		Fetched:          time.Now(),
		URL:              p.URL,
	}
}

// anchoredIDs garde les identifiants CVE/GHSA proposés par le modèle qui figurent bien dans
// le texte, normalisés et dédoublonnés.
func anchoredIDs(proposed []string, text string) []string {
	inText := map[string]bool{}
	for _, c := range idRe.FindAllString(text, -1) {
		inText[normalizeID(c)] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range proposed {
		c = normalizeID(strings.TrimSpace(c))
		if inText[c] && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// normalizeID met en forme CVE-2026-1234 et GHSA-abcd-efgh-ijkl.
func normalizeID(id string) string {
	if len(id) > 5 && strings.EqualFold(id[:5], "GHSA-") {
		return "GHSA-" + strings.ToLower(id[5:])
	}
	return strings.ToUpper(id)
}

// anchoredVersions retire les éléments dont un numéro de version n'apparaît
// pas dans le texte.
func anchoredVersions(s, text string) string {
	var kept []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ok := true
		for _, v := range versionRe.FindAllString(part, -1) {
			if !strings.Contains(text, v) {
				ok = false
				break
			}
		}
		if ok {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, ", ")
}

func canonicalURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String()
}
