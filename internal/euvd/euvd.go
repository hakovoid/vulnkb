// Package euvd lit la base européenne des vulnérabilités (EUVD) de l'ENISA,
// ouverte en 2025. Elle reprend les CVE sous un identifiant européen
// (EUVD-AAAA-N), cité par les bulletins des CSIRT de l'Union, et tient sa
// propre liste de failles exploitées.
//
// Son contenu recoupe la liste officielle des CVE : vulnkb n'en garde que
// l'apport propre — l'identifiant EUVD de chaque CVE et le marqueur
// « exploitée ». L'API ne rend que 100 fiches par page ; la collecte se
// limite donc à la liste des exploitées (complète) et aux fiches mises à jour
// sur une période.
package euvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	SearchURL = "https://euvdservices.enisa.europa.eu/api/search"
	PageURL   = "https://euvd.enisa.europa.eu/vulnerability/"
	pageSize  = 100
	userAgent = "vulnkb (+https://github.com/hakovoid/vulnkb)"
)

// Record est ce que vulnkb garde d'une fiche EUVD.
type Record struct {
	ID             string    // EUVD-2026-72027
	CVEs           []string  // alias CVE
	ExploitedSince time.Time // zéro si l'ENISA ne la signale pas exploitée
}

var (
	idRe  = regexp.MustCompile(`^EUVD-\d{4}-\d+$`)
	cveRe = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
)

// IsID dit si s est un identifiant EUVD.
func IsID(s string) bool { return idRe.MatchString(strings.ToUpper(s)) }

type item struct {
	ID             string `json:"id"`
	Aliases        string `json:"aliases"`
	ExploitedSince string `json:"exploitedSince"`
}

// parseTime lit le format de l'API : « Sep 27, 2026, 12:00:00 AM ».
func parseTime(s string) time.Time {
	t, _ := time.Parse("Jan 2, 2006, 3:04:05 PM", strings.TrimSpace(s))
	return t
}

func (it item) record() Record {
	r := Record{ID: it.ID, CVEs: cveRe.FindAllString(it.Aliases, -1)}
	if it.ExploitedSince != "" {
		r.ExploitedSince = parseTime(it.ExploitedSince)
		if r.ExploitedSince.IsZero() { // date illisible : exploitée quand même
			r.ExploitedSince = time.Unix(1, 0)
		}
	}
	return r
}

// Query restreint une collecte.
type Query struct {
	Exploited   bool      // seulement les failles exploitées
	UpdatedFrom time.Time // fiches mises à jour depuis ce jour (zéro : toutes)
}

// Pause entre deux pages, et attentes avant de réessayer quand le service
// limite le débit (statut 403 ou 429). Variables pour les tests.
var (
	Pause   = 400 * time.Millisecond
	Backoff = []time.Duration{30 * time.Second, 60 * time.Second}
)

// errThrottled signale une limitation de débit du service.
var errThrottled = fmt.Errorf("débit limité par le service")

// getPolitely est getJSON avec de nouvelles tentatives espacées quand le
// service limite le débit.
func getPolitely(ctx context.Context, client *http.Client, u string, v any) error {
	err := getJSON(ctx, client, u, v)
	for _, wait := range Backoff {
		if !errors.Is(err, errThrottled) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		err = getJSON(ctx, client, u, v)
	}
	return err
}

// Fetch parcourt les pages de résultats et appelle emit pour chaque fiche.
// Une pause entre les pages ménage le service public.
func Fetch(ctx context.Context, client *http.Client, base string, q Query, emit func(Record) error) error {
	params := url.Values{"size": {strconv.Itoa(pageSize)}}
	if q.Exploited {
		params.Set("exploited", "true")
	}
	if !q.UpdatedFrom.IsZero() {
		params.Set("fromUpdatedDate", q.UpdatedFrom.Format("2006-01-02"))
		params.Set("toUpdatedDate", time.Now().AddDate(0, 0, 1).Format("2006-01-02"))
	}
	for page, seen := 0, 0; ; page++ {
		params.Set("page", strconv.Itoa(page))
		var res struct {
			Items []item `json:"items"`
			Total int    `json:"total"`
		}
		if err := getPolitely(ctx, client, base+"?"+params.Encode(), &res); err != nil {
			return fmt.Errorf("EUVD page %d : %w", page, err)
		}
		for _, it := range res.Items {
			if it.ID == "" {
				continue
			}
			if err := emit(it.record()); err != nil {
				return err
			}
		}
		seen += len(res.Items)
		if len(res.Items) < pageSize || seen >= res.Total {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(Pause):
		}
	}
}

func getJSON(ctx context.Context, client *http.Client, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusTooManyRequests:
		return fmt.Errorf("%w (statut %d)", errThrottled, resp.StatusCode)
	default:
		return fmt.Errorf("statut %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}
