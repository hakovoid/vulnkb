// Sources OSV.dev : une par écosystème de paquets. OSV n'offre pas d'API pour
// tout lister, on télécharge donc l'export complet de l'écosystème (all.zip),
// un fichier JSON par vulnérabilité au format OSV.
package source

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"vulnkb/internal/model"
)

const osvBucket = "https://osv-vulnerabilities.storage.googleapis.com/"

func init() {
	for _, e := range []struct {
		name, ecosystem string
		optional        bool
	}{
		{"osv-go", "Go", false},
		{"osv-pypi", "PyPI", false},
		{"osv-packagist", "Packagist", false},
		{"osv-crates", "crates.io", false},
		{"osv-maven", "Maven", false},
		{"osv-npm", "npm", true}, // export de ~200 Mo
	} {
		Register(&osv{name: e.name, ecosystem: e.ecosystem, optional: e.optional, client: http.DefaultClient})
	}
}

type osv struct {
	name, ecosystem string
	optional        bool
	client          *http.Client
}

func (o *osv) Name() string   { return o.name }
func (o *osv) Optional() bool { return o.optional }

func (o *osv) Fetch(ctx context.Context, since time.Time) ([]model.Advisory, error) {
	tmp, err := os.CreateTemp("", "vulnkb-osv-*.zip")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, osvBucket+o.ecosystem+"/all.zip", nil)
	if err != nil {
		return nil, err
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("téléchargement OSV %s: %w", o.ecosystem, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV %s: statut %d", o.ecosystem, resp.StatusCode)
	}
	size, err := io.Copy(tmp, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("téléchargement OSV %s: %w", o.ecosystem, err)
	}

	zr, err := zip.NewReader(tmp, size)
	if err != nil {
		return nil, fmt.Errorf("archive OSV %s: %w", o.ecosystem, err)
	}
	return parseOSVZip(zr, since)
}

// parseOSVZip lit chaque entrée de l'archive. Les fichiers sont triés pour
// que le choix entre alias (GHSA-… / GO-…) soit déterministe.
func parseOSVZip(zr *zip.Reader, since time.Time) ([]model.Advisory, error) {
	files := append([]*zip.File(nil), zr.File...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	seen := map[string]bool{}
	now := time.Now()
	var out []model.Advisory
	for _, f := range files {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		var v osvVuln
		err = json.NewDecoder(rc).Decode(&v)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("décodage OSV %s: %w", f.Name, err)
		}
		if !keepOSV(v, since, seen) {
			continue
		}
		a := v.toAdvisory()
		a.Fetched = now
		out = append(out, a)
	}
	return out, nil
}

// keepOSV écarte les entrées retirées, les paquets malveillants (MAL-*),
// celles antérieures à since, et les alias d'une faille déjà retenue.
func keepOSV(v osvVuln, since time.Time, seen map[string]bool) bool {
	if v.ID == "" || v.Withdrawn != "" || strings.HasPrefix(v.ID, "MAL-") {
		return false
	}
	if !since.IsZero() && parseRFC3339(v.Modified).Before(since) {
		return false
	}
	ids := append([]string{v.ID}, v.Aliases...)
	for _, id := range ids {
		if seen[id] {
			return false
		}
	}
	for _, id := range ids {
		seen[id] = true
	}
	return true
}

type osvVuln struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Aliases   []string `json:"aliases"`
	Modified  string   `json:"modified"`
	Published string   `json:"published"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string   `json:"severity"`
		CWEIDs   []string `json:"cwe_ids"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

func (v osvVuln) toAdvisory() model.Advisory {
	var (
		pkgs, affected, fixed, remediation []string
		pkgSeen                            = map[string]bool{}
	)
	for _, af := range v.Affected {
		name := af.Package.Name
		if name != "" && !pkgSeen[name] {
			pkgSeen[name] = true
			pkgs = append(pkgs, name)
		}
		for _, r := range af.Ranges {
			rng, fix := describeRange(r.Events)
			if rng != "" {
				affected = append(affected, name+" "+rng)
			}
			for _, f := range fix {
				fixed = append(fixed, name+" "+f)
				remediation = append(remediation, "mettre à jour "+name+" en "+f+" ou plus")
			}
		}
	}

	title := v.Summary
	if title == "" {
		title = firstLine(v.Details)
	}
	externalID := v.ID
	if len(v.Aliases) > 0 {
		externalID += " (" + strings.Join(v.Aliases, ", ") + ")"
	}
	var refs []string
	for _, r := range v.References {
		if r.URL != "" {
			refs = append(refs, r.URL)
		}
	}
	component := ""
	if len(v.Affected) > 0 {
		component = v.Affected[0].Package.Ecosystem + " " + strings.Join(pkgs, ", ")
	}
	rem := strings.Join(dedup(remediation), " ; ")
	if rem != "" {
		rem = strings.ToUpper(rem[:1]) + rem[1:] + "."
	}

	return model.Advisory{
		ID:               "osv:" + v.ID,
		Source:           "osv",
		ExternalID:       externalID,
		Title:            title,
		Summary:          v.Details,
		Component:        strings.TrimSpace(component),
		VulnType:         strings.Join(v.DatabaseSpecific.CWEIDs, ", "),
		Severity:         osvSeverity(v),
		AffectedVersions: strings.Join(dedup(affected), " ; "),
		FixedVersions:    strings.Join(dedup(fixed), " ; "),
		Remediation:      rem,
		References:       refs,
		Published:        parseRFC3339(v.Published),
		URL:              "https://osv.dev/vulnerability/" + v.ID,
	}
}

// describeRange transforme les événements OSV (introduced / fixed /
// last_affected) en intervalle lisible, et renvoie les versions correctives.
func describeRange(events []map[string]string) (string, []string) {
	var parts, fixed []string
	for _, ev := range events {
		switch {
		case ev["introduced"] != "":
			if ev["introduced"] != "0" {
				parts = append(parts, ">= "+ev["introduced"])
			}
		case ev["fixed"] != "":
			parts = append(parts, "< "+ev["fixed"])
			fixed = append(fixed, ev["fixed"])
		case ev["last_affected"] != "":
			parts = append(parts, "<= "+ev["last_affected"])
		}
	}
	if len(parts) == 0 {
		return "toutes versions", fixed
	}
	return strings.Join(parts, " "), fixed
}

func osvSeverity(v osvVuln) string {
	if s := v.DatabaseSpecific.Severity; s != "" {
		return s
	}
	if len(v.Severity) > 0 {
		return v.Severity[0].Score
	}
	return ""
}

func parseRFC3339(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if r := []rune(s); len(r) > 120 {
		s = string(r[:120]) + "…"
	}
	return s
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
