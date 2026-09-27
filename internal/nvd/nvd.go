// Package nvd récupère les scores CVSS de la base NVD (NIST) à partir de
// ses flux JSON 2.0 : un fichier compressé par année, plus un flux des CVE
// modifiés sur les 8 derniers jours. Les flux n'ont ni clé ni limite de
// débit, contrairement à l'API.
package nvd

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"vulnkb/internal/model"
)

const FeedBase = "https://nvd.nist.gov/feeds/json/cve/2.0/"

// FirstYear est le premier flux annuel ; il contient aussi les CVE de 1999 à 2001.
const FirstYear = 2002

// Fetch lit un flux (ex. "2024" ou "modified") et appelle emit pour chaque
// CVE doté d'un score. Le fichier est décodé au fil de l'eau.
func Fetch(ctx context.Context, client *http.Client, base, feed string, emit func(model.CVSS) error) error {
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
func Parse(r io.Reader, emit func(model.CVSS) error) error {
	dec := json.NewDecoder(r)
	if err := seekArray(dec, "vulnerabilities"); err != nil {
		return err
	}
	for dec.More() {
		var item struct {
			CVE cveRecord `json:"cve"`
		}
		if err := dec.Decode(&item); err != nil {
			return err
		}
		if s, ok := item.CVE.best(); ok {
			if err := emit(s); err != nil {
				return err
			}
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

type cveRecord struct {
	ID         string `json:"id"`
	VulnStatus string `json:"vulnStatus"`
	Metrics    struct {
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
