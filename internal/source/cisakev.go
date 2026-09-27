// Source d'exemple : le catalogue CISA KEV (Known Exploited Vulnerabilities).
// C'est un fichier JSON public, sans clé API, ce qui en fait une bonne
// première source pour valider toute la chaîne (fetch -> normalise -> store).
//
// Pour ajouter une autre source structurée (NVD, OSV, GHSA…), copier ce
// modèle : un type qui implémente source.Source et s'enregistre dans init().
package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"vulnkb/internal/model"
)

const kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

func init() { Register(&cisaKEV{client: &http.Client{Timeout: 60 * time.Second}}) }

type cisaKEV struct{ client *http.Client }

func (c *cisaKEV) Name() string { return "cisa-kev" }

// Structure partielle du flux CISA KEV (on ne mappe que ce qui nous sert).
type kevFeed struct {
	Vulnerabilities []struct {
		CveID             string `json:"cveID"`
		VendorProject     string `json:"vendorProject"`
		Product           string `json:"product"`
		VulnerabilityName string `json:"vulnerabilityName"`
		DateAdded         string `json:"dateAdded"`
		ShortDescription  string `json:"shortDescription"`
		RequiredAction    string `json:"requiredAction"`
		Notes             string `json:"notes"`
	} `json:"vulnerabilities"`
}

func (c *cisaKEV) Fetch(ctx context.Context, since time.Time) ([]model.Advisory, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kevURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requête CISA KEV: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CISA KEV: statut %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var feed kevFeed
	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("décodage CISA KEV: %w", err)
	}

	now := time.Now()
	out := make([]model.Advisory, 0, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		pub := parseDate(v.DateAdded)
		if !since.IsZero() && pub.Before(since) {
			continue
		}
		nvd := "https://nvd.nist.gov/vuln/detail/" + v.CveID
		out = append(out, model.Advisory{
			ID:          "cisa-kev:" + v.CveID,
			Source:      c.Name(),
			ExternalID:  v.CveID,
			Title:       v.VulnerabilityName,
			Summary:     v.ShortDescription,
			Component:   v.VendorProject + " " + v.Product,
			Severity:    "Known Exploited",
			Remediation: strings.TrimSpace(v.RequiredAction),
			References:  noteRefs(nvd, v.Notes),
			Published:   pub,
			Fetched:     now,
			URL:         nvd,
		})
	}
	return out, nil
}

var urlRe = regexp.MustCompile(`https?://[^\s;,]+`)

// noteRefs renvoie le lien NVD suivi des URL (avis éditeur, correctif…)
// listées dans le champ notes du flux KEV, sans doublon.
func noteRefs(nvd, notes string) []string {
	refs := []string{nvd}
	seen := map[string]bool{nvd: true}
	for _, u := range urlRe.FindAllString(notes, -1) {
		u = strings.TrimRight(u, ".)")
		if !seen[u] {
			seen[u] = true
			refs = append(refs, u)
		}
	}
	return refs
}

func parseDate(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}
	}
	return t
}
