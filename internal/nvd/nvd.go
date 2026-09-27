// Package nvd lit la base NVD (NIST) à partir de ses flux JSON 2.0 : un
// fichier compressé par année, plus un flux des CVE modifiés sur les 8
// derniers jours. Les flux n'ont ni clé ni limite de débit, contrairement à
// l'API. Chaque CVE donne une entrée (description, produits, versions,
// références) et, s'il est évalué, un score CVSS.
package nvd

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"vulnkb/internal/model"
)

const FeedBase = "https://nvd.nist.gov/feeds/json/cve/2.0/"

// FirstYear est le premier flux annuel ; il contient aussi les CVE de 1999 à 2001.
const FirstYear = 2002

// Source est la valeur de model.Advisory.Source des entrées NVD.
const Source = "nvd"

// Record est ce que le flux apprend sur un CVE.
type Record struct {
	CVE      string
	Rejected bool // CVE retiré : l'entrée éventuelle doit être supprimée
	Advisory model.Advisory
	Score    model.CVSS // zéro si le CVE n'est pas encore évalué
	// ExploitRefs sont les références que NVD étiquette « Exploit ».
	ExploitRefs []string
}

// Fetch lit un flux (ex. "2024" ou "modified") et appelle emit pour chaque
// CVE. Le fichier est décodé au fil de l'eau.
func Fetch(ctx context.Context, client *http.Client, base, feed string, emit func(Record) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"nvdcve-2.0-"+feed+".json.gz", nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "vulnkb (+https://github.com/hakovoid/vulnkb)")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("flux NVD %s: %w", feed, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("flux NVD %s: statut %d", feed, resp.StatusCode)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("flux NVD %s: %w", feed, err)
	}
	defer gz.Close()
	if err := Parse(gz, emit); err != nil {
		return fmt.Errorf("flux NVD %s: %w", feed, err)
	}
	return nil
}

// Parse décode un flux NVD 2.0 non compressé.
func Parse(r io.Reader, emit func(Record) error) error {
	dec := json.NewDecoder(r)
	if err := seekArray(dec, "vulnerabilities"); err != nil {
		return err
	}
	now := time.Now()
	for dec.More() {
		var item struct {
			CVE cveRecord `json:"cve"`
		}
		if err := dec.Decode(&item); err != nil {
			return err
		}
		c := item.CVE
		if c.ID == "" {
			continue
		}
		rec := Record{CVE: c.ID, Rejected: c.VulnStatus == "Rejected"}
		if !rec.Rejected {
			rec.Score, _ = c.best()
			rec.Advisory = c.toAdvisory(rec.Score)
			rec.Advisory.Fetched = now
			rec.ExploitRefs = c.exploitRefs()
		}
		if err := emit(rec); err != nil {
			return err
		}
	}
	return nil
}

// seekArray avance le décodeur jusqu'au début du tableau de la clé donnée,
// au premier niveau de l'objet.
func seekArray(dec *json.Decoder, key string) error {
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return fmt.Errorf("objet JSON attendu")
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if t == key {
			if t, err := dec.Token(); err != nil || t != json.Delim('[') {
				return fmt.Errorf("tableau %q attendu", key)
			}
			return nil
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return err
		}
	}
	return fmt.Errorf("clé %q absente", key)
}

type metric struct {
	Source       string `json:"source"`
	Type         string `json:"type"`
	BaseSeverity string `json:"baseSeverity"` // CVSS 2 : hors de cvssData
	CVSSData     struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

type cpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type cveRecord struct {
	ID           string `json:"id"`
	VulnStatus   string `json:"vulnStatus"`
	Published    string `json:"published"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V40 []metric `json:"cvssMetricV40"`
		V31 []metric `json:"cvssMetricV31"`
		V30 []metric `json:"cvssMetricV30"`
		V2  []metric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []struct {
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []cpeMatch `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	References []struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags"`
	} `json:"references"`
}

// best retient un score par CVE : CVSS 3.x d'abord (le plus répandu et celui
// des autres sources), puis 4.0, puis 2.0 ; à version égale, celui de NVD
// (« Primary ») avant celui de l'émetteur.
func (c cveRecord) best() (model.CVSS, bool) {
	if c.ID == "" || c.VulnStatus == "Rejected" {
		return model.CVSS{}, false
	}
	for _, group := range [][]metric{c.Metrics.V31, c.Metrics.V30, c.Metrics.V40, c.Metrics.V2} {
		m, ok := pick(group)
		if !ok {
			continue
		}
		sev := m.CVSSData.BaseSeverity
		if sev == "" {
			sev = m.BaseSeverity
		}
		level := model.ParseSeverity(sev).Level
		if level == model.SevUnknown {
			level = model.LevelForScore(m.CVSSData.BaseScore)
		}
		return model.CVSS{
			CVE:     c.ID,
			Score:   m.CVSSData.BaseScore,
			Level:   level,
			Version: m.CVSSData.Version,
			Vector:  m.CVSSData.VectorString,
			Source:  m.Source,
			CWE:     c.cwes(),
		}, true
	}
	return model.CVSS{}, false
}

func pick(ms []metric) (metric, bool) {
	for _, m := range ms {
		if m.Type == "Primary" {
			return m, true
		}
	}
	if len(ms) > 0 {
		return ms[0], true
	}
	return metric{}, false
}

func (c cveRecord) cwes() string {
	seen := map[string]bool{}
	var out []string
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") && !seen[d.Value] {
				seen[d.Value] = true
				out = append(out, d.Value)
			}
		}
	}
	return strings.Join(out, ", ")
}

var sevNames = [...]string{"", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

const (
	maxProducts = 10
	maxRanges   = 15
	maxRefs     = 30
)

func (c cveRecord) toAdvisory(score model.CVSS) model.Advisory {
	desc := ""
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			desc = strings.TrimSpace(d.Value)
			break
		}
	}
	products, affected, fixed := c.cpeSummary()

	var refs []string
	for _, r := range c.References {
		if r.URL != "" && len(refs) < maxRefs {
			refs = append(refs, r.URL)
		}
	}
	url := "https://nvd.nist.gov/vuln/detail/" + c.ID
	return model.Advisory{
		ID:               Source + ":" + c.ID,
		Source:           Source,
		ExternalID:       c.ID,
		Title:            titleFrom(desc, c.ID),
		Summary:          desc,
		Component:        strings.Join(products, ", "),
		VulnType:         c.cwes(),
		Severity:         sevNames[score.Level],
		AffectedVersions: strings.Join(affected, " ; "),
		FixedVersions:    strings.Join(fixed, " ; "),
		References:       append([]string{url}, refs...),
		Published:        parseNVDTime(c.Published),
		URL:              url,
	}
}

// cpeSummary tire des configurations CPE les produits touchés, les plages de
// versions vulnérables et les versions correctives.
func (c cveRecord) cpeSummary() (products, affected, fixed []string) {
	seenP, seenA, seenF := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, conf := range c.Configurations {
		for _, n := range conf.Nodes {
			for _, m := range n.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				// cpe:2.3:part:vendor:product:version:…
				f := strings.Split(m.Criteria, ":")
				if len(f) < 6 {
					continue
				}
				vendor, product, version := unescape(f[3]), unescape(f[4]), f[5]
				name := product
				if !strings.HasPrefix(product, vendor) {
					name = vendor + " " + product
				}
				name = strings.ReplaceAll(name, "_", " ")
				if !seenP[name] && len(products) < maxProducts {
					seenP[name] = true
					products = append(products, name)
				}

				var r []string
				if m.VersionStartIncluding != "" {
					r = append(r, ">= "+m.VersionStartIncluding)
				}
				if m.VersionStartExcluding != "" {
					r = append(r, "> "+m.VersionStartExcluding)
				}
				if m.VersionEndIncluding != "" {
					r = append(r, "<= "+m.VersionEndIncluding)
				}
				if m.VersionEndExcluding != "" {
					r = append(r, "< "+m.VersionEndExcluding)
					if !seenF[name+m.VersionEndExcluding] {
						seenF[name+m.VersionEndExcluding] = true
						fixed = append(fixed, name+" "+m.VersionEndExcluding)
					}
				}
				if len(r) == 0 && version != "*" && version != "-" {
					r = append(r, "= "+unescape(version))
				}
				if len(r) > 0 {
					a := name + " " + strings.Join(r, " ")
					if !seenA[a] && len(affected) < maxRanges {
						seenA[a] = true
						affected = append(affected, a)
					}
				}
			}
		}
	}
	return products, affected, fixed
}

// exploitRefs renvoie les références étiquetées « Exploit » par NVD.
func (c cveRecord) exploitRefs() []string {
	var out []string
	for _, r := range c.References {
		for _, t := range r.Tags {
			if t == "Exploit" {
				out = append(out, r.URL)
				break
			}
		}
	}
	return out
}

// titleFrom fabrique un titre à partir de la description (NVD n'en a pas) :
// la première phrase, tronquée.
func titleFrom(desc, id string) string {
	if desc == "" {
		return id
	}
	t := desc
	if i := strings.Index(t, ". "); i > 0 {
		t = t[:i]
	}
	t = strings.Join(strings.Fields(t), " ")
	if r := []rune(t); len(r) > 140 {
		t = string(r[:140]) + "…"
	}
	return t
}

func unescape(s string) string { return strings.ReplaceAll(s, `\`, "") }

func parseNVDTime(s string) time.Time {
	for _, l := range []string{"2006-01-02T15:04:05.000", "2006-01-02T15:04:05", time.RFC3339} {
		if t, err := time.Parse(l, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
