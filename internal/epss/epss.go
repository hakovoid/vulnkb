// Package epss récupère les scores EPSS (Exploit Prediction Scoring System)
// publiés chaque jour par le FIRST : pour chaque CVE, la probabilité qu'il
// soit exploité dans les 30 jours à venir, et son centile parmi tous les CVE.
package epss

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// FeedURL est le fichier quotidien complet (CSV compressé).
const FeedURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

// Score est la prévision EPSS d'un CVE.
type Score struct {
	CVE        string
	Score      float64 // probabilité d'exploitation sous 30 jours (0 à 1)
	Percentile float64 // part des CVE ayant un score inférieur (0 à 1)
}

// Fetch télécharge le fichier du jour ; renvoie les scores et leur date.
func Fetch(ctx context.Context, client *http.Client, url string) ([]Score, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	req.Header.Set("User-Agent", "vulnkb (+https://github.com/hakovoid/vulnkb)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, fmt.Errorf("EPSS : statut %d", resp.StatusCode)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer gz.Close()
	return Parse(gz)
}

// Parse lit le CSV EPSS : une ligne de commentaire
// (« #model_version:…,score_date:2026-09-27T12:00:21Z »), l'en-tête
// « cve,epss,percentile », puis une ligne par CVE.
func Parse(r io.Reader) ([]Score, time.Time, error) {
	var (
		out  []Score
		date time.Time
	)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "#"):
			for _, kv := range strings.Split(strings.TrimPrefix(line, "#"), ",") {
				if k, v, ok := strings.Cut(kv, ":"); ok && k == "score_date" {
					date, _ = time.Parse(time.RFC3339, v)
				}
			}
			continue
		case strings.HasPrefix(line, "cve,"):
			continue
		}
		f := strings.Split(line, ",")
		if len(f) < 3 || !strings.HasPrefix(f[0], "CVE-") {
			continue
		}
		s, err1 := strconv.ParseFloat(f[1], 64)
		p, err2 := strconv.ParseFloat(f[2], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, Score{CVE: f[0], Score: s, Percentile: p})
	}
	if err := sc.Err(); err != nil {
		return nil, date, err
	}
	if len(out) == 0 {
		return nil, date, fmt.Errorf("EPSS : aucun score lu")
	}
	return out, date, nil
}
