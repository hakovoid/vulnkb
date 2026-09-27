// Source CERT-FR (ANSSI) : avis et alertes de sécurité en français, via
// l'API JSON publique (https://www.cert.ssi.gouv.fr/openapi.json). La liste
// ne donne que la référence et la date de révision ; le détail (CVE,
// systèmes affectés, solutions) demande une requête par bulletin.
package source

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vulnkb/internal/model"
)

const certfrBase = "https://www.cert.ssi.gouv.fr"

func init() {
	days := 365
	if v, err := strconv.Atoi(os.Getenv("VULNKB_CERTFR_DAYS")); err == nil && v > 0 {
		days = v
	}
	Register(&certfr{
		base:    certfrBase,
		client:  &http.Client{Timeout: 30 * time.Second},
		days:    days,
		workers: 4,
	})
}

type certfr struct {
	base    string
	client  *http.Client
	days    int // fenêtre de la première collecte
	workers int
}

func (c *certfr) Name() string      { return "certfr" }
func (c *certfr) Incremental() bool { return true }

type certfrItem struct {
	Reference        string `json:"reference"`
	JSONURL          string `json:"json_url"`
	LastRevisionDate string `json:"last_revision_date"`
	alert            bool
}

type certfrDetail struct {
	Reference       string `json:"reference"`
	Title           string `json:"title"`
	Summary         string `json:"summary"`
	Content         string `json:"content"`
	ClosedAt        string `json:"closed_at"`
	AffectedSystems []struct {
		Description string `json:"description"`
		Product     struct {
			Name   string `json:"name"`
			Vendor struct {
				Name string `json:"name"`
			} `json:"vendor"`
		} `json:"product"`
	} `json:"affected_systems"`
	CVEs []struct {
		Name string `json:"name"`
	} `json:"cves"`
	Risks []struct {
		Description string `json:"description"`
	} `json:"risks"`
	Revisions []struct {
		RevisionDate string `json:"revision_date"`
	} `json:"revisions"`
	VendorAdvisories []struct {
		URL string `json:"url"`
	} `json:"vendor_advisories"`
	Links []struct {
		URL string `json:"url"`
	} `json:"links"`
}

// Fetch collecte les bulletins révisés depuis since (moins une marge), ou
// ceux de la fenêtre configurée lors de la première collecte.
func (c *certfr) Fetch(ctx context.Context, since time.Time) ([]model.Advisory, error) {
	cutoff := time.Now().AddDate(0, 0, -c.days)
	if !since.IsZero() {
		cutoff = since.Add(-48 * time.Hour)
	}

	var items []certfrItem
	for _, kind := range []string{"avis", "alerte"} {
		var list []certfrItem
		if err := c.getJSON(ctx, "/"+kind+"/json/", &list); err != nil {
			return nil, fmt.Errorf("liste CERT-FR %s: %w", kind, err)
		}
		for _, it := range list {
			if !parseCertfrDate(it.LastRevisionDate).Before(cutoff) {
				it.alert = kind == "alerte"
				items = append(items, it)
			}
		}
	}

	out, failed := c.fetchDetails(ctx, items)
	if len(items) > 0 && failed*20 > len(items) { // plus de 5 % d'échecs
		return nil, fmt.Errorf("CERT-FR: %d bulletins sur %d illisibles", failed, len(items))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (c *certfr) fetchDetails(ctx context.Context, items []certfrItem) ([]model.Advisory, int) {
	var (
		mu     sync.Mutex
		out    []model.Advisory
		failed int
		wg     sync.WaitGroup
		queue  = make(chan certfrItem)
	)
	now := time.Now()
	for w := 0; w < c.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range queue {
				var d certfrDetail
				err := c.getJSON(ctx, it.JSONURL, &d)
				if err != nil && ctx.Err() == nil {
					err = c.getJSON(ctx, it.JSONURL, &d) // une seconde chance
				}
				mu.Lock()
				if err != nil {
					failed++
				} else {
					a := d.toAdvisory(c.base, it.alert)
					a.Fetched = now
					out = append(out, a)
				}
				mu.Unlock()
			}
		}()
	}
	for _, it := range items {
		select {
		case queue <- it:
		case <-ctx.Done():
		}
	}
	close(queue)
	wg.Wait()
	return out, failed
}

func (c *certfr) getJSON(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "vulnkb (+https://github.com/hakovoid/vulnkb)")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: statut %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

var (
	tagRe          = regexp.MustCompile(`<[^>]+>`)
	solutionHeadRe = regexp.MustCompile(`(?im)^##\s*Solutions?\s*$`)
	nextHeadRe     = regexp.MustCompile(`(?m)^##\s`)
)

func (d certfrDetail) toAdvisory(base string, alert bool) model.Advisory {
	kind := "avis"
	if alert {
		kind = "alerte"
	}
	pageURL := base + "/" + kind + "/" + d.Reference + "/"

	var cves []string
	for _, c := range d.CVEs {
		if c.Name != "" {
			cves = append(cves, c.Name)
		}
	}
	externalID := d.Reference
	if len(cves) > 0 {
		externalID += " (" + strings.Join(cves, ", ") + ")"
	}

	var products, systems []string
	for _, s := range d.AffectedSystems {
		name := strings.TrimSpace(s.Product.Vendor.Name + " " + strings.TrimPrefix(s.Product.Name, "N/A"))
		if name != "" {
			products = append(products, name)
		}
		if desc := stripHTML(s.Description); desc != "" {
			systems = append(systems, "• "+desc)
		}
	}
	var risks []string
	for _, r := range d.Risks {
		risks = append(risks, stripHTML(r.Description))
	}

	remediation, rest := splitSolution(d.Content)
	summary := stripHTML(d.Summary)
	if alert {
		status := "en cours"
		if d.ClosedAt != "" {
			status = "close le " + d.ClosedAt[:min(10, len(d.ClosedAt))]
		}
		summary = "Alerte CERT-FR (menace active), " + status + ".\n\n" + summary
	}
	if rest != "" {
		summary += "\n\n" + rest
	}

	refs := []string{pageURL}
	seen := map[string]bool{pageURL: true}
	addRef := func(u string) {
		abs := resolveURL(base, u)
		if abs != "" && !seen[abs] {
			seen[abs] = true
			refs = append(refs, abs)
		}
	}
	for _, v := range d.VendorAdvisories {
		addRef(v.URL)
	}
	for _, l := range d.Links {
		addRef(l.URL)
	}

	var published time.Time
	for _, r := range d.Revisions {
		if t := parseCertfrDate(r.RevisionDate); !t.IsZero() && (published.IsZero() || t.Before(published)) {
			published = t
		}
	}

	title := stripHTML(d.Title)
	if alert {
		title = "Alerte : " + title
	}
	return model.Advisory{
		ID:               "certfr:" + d.Reference,
		Source:           "certfr",
		ExternalID:       externalID,
		Title:            title,
		Summary:          summary,
		Component:        strings.Join(dedup(products), ", "),
		VulnType:         strings.Join(dedup(risks), ", "),
		AffectedVersions: strings.Join(dedup(systems), "\n"),
		Remediation:      remediation,
		References:       refs,
		Published:        published,
		URL:              pageURL,
	}
}

// splitSolution isole la section « ## Solution(s) » du contenu Markdown.
func splitSolution(content string) (solution, rest string) {
	content = strings.TrimSpace(content)
	loc := solutionHeadRe.FindStringIndex(content)
	if loc == nil {
		return "", content
	}
	body := content[loc[1]:]
	end := len(body)
	if n := nextHeadRe.FindStringIndex(body); n != nil {
		end = n[0]
	}
	solution = strings.TrimSpace(body[:end])
	rest = strings.TrimSpace(content[:loc[0]] + "\n\n" + body[end:])
	return solution, rest
}

func stripHTML(s string) string {
	s = html.UnescapeString(tagRe.ReplaceAllString(s, ""))
	return strings.Join(strings.Fields(s), " ")
}

func resolveURL(base, u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	b, err := url.Parse(base + "/")
	if err != nil {
		return u
	}
	r, err := b.Parse(u)
	if err != nil {
		return u
	}
	return r.String()
}

func parseCertfrDate(s string) time.Time {
	for _, l := range []string{"2006-01-02T15:04:05.999999", time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(l, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
