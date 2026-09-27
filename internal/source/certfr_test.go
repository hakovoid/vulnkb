package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func certfrServer(t *testing.T, hits *[]string) *httptest.Server {
	t.Helper()
	recent := time.Now().AddDate(0, 0, -10).Format("2006-01-02T15:04:05.000000")
	old := time.Now().AddDate(-3, 0, 0).Format("2006-01-02T15:04:05.000000")
	pages := map[string]string{
		"/avis/json/": `[
			{"reference":"CERTFR-2026-AVI-0001","json_url":"/avis/CERTFR-2026-AVI-0001/json/","last_revision_date":"` + recent + `"},
			{"reference":"CERTFR-2023-AVI-0999","json_url":"/avis/CERTFR-2023-AVI-0999/json/","last_revision_date":"` + old + `"}]`,
		"/alerte/json/": `[
			{"reference":"CERTFR-2026-ALE-001","json_url":"/alerte/CERTFR-2026-ALE-001/json/","last_revision_date":"` + recent + `"}]`,
		"/avis/CERTFR-2026-AVI-0001/json/": `{
			"reference":"CERTFR-2026-AVI-0001",
			"title":"Multiples vulnérabilités dans F5 NGINX",
			"summary":"De multiples vulnérabilités ont été découvertes dans <span class=\"textit\">F5 NGINX</span>.",
			"content":"## Solutions\n\nSe référer au bulletin de l'éditeur.\n\n## Documentation\n\nVoir les liens.",
			"affected_systems":[
				{"description":"NGINX Plus versions antérieures à R36 P2","product":{"name":"NGINX Plus","vendor":{"name":"F5"}}},
				{"description":"NGINX Open Source versions 1.29.x antérieures à 1.29.4","product":{"name":"NGINX Open Source","vendor":{"name":"F5"}}}],
			"cves":[{"name":"CVE-2026-1111"},{"name":"CVE-2026-2222"}],
			"risks":[{"description":"Déni de service à distance"},{"description":"Déni de service à distance"}],
			"revisions":[{"revision_date":"2026-09-16T00:00:00.000000"},{"revision_date":"2026-09-01T00:00:00.000000"}],
			"vendor_advisories":[{"url":"https://my.f5.com/manage/s/article/K000"}],
			"links":[{"url":"/avis/CERTFR-2026-AVI-0000/"}]}`,
		"/alerte/CERTFR-2026-ALE-001/json/": `{
			"reference":"CERTFR-2026-ALE-001","title":"Vulnérabilité dans Ivanti","summary":"Exploitation active.",
			"content":"## Solution\n\nAppliquer le correctif.","closed_at":"",
			"cves":[{"name":"CVE-2026-3333"}],"risks":[{"description":"Exécution de code arbitraire à distance"}],
			"revisions":[{"revision_date":"2026-09-20T00:00:00.000000"}]}`,
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits = append(*hits, r.URL.Path)
		body, ok := pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	}))
}

func TestCertfrFetch(t *testing.T) {
	var hits []string
	srv := certfrServer(t, &hits)
	defer srv.Close()
	c := &certfr{base: srv.URL, client: srv.Client(), days: 365, workers: 2}

	advs, err := c.Fetch(context.Background(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 2 {
		t.Fatalf("attendu 2 bulletins (l'ancien hors fenêtre), obtenu %d", len(advs))
	}
	for _, h := range hits {
		if strings.Contains(h, "2023") {
			t.Errorf("bulletin hors fenêtre téléchargé: %s", h)
		}
	}

	ale, avi := advs[0], advs[1] // triés par ID
	checks := map[string][2]string{
		"ID":          {avi.ID, "certfr:CERTFR-2026-AVI-0001"},
		"ExternalID":  {avi.ExternalID, "CERTFR-2026-AVI-0001 (CVE-2026-1111, CVE-2026-2222)"},
		"Component":   {avi.Component, "F5 NGINX Plus, F5 NGINX Open Source"},
		"VulnType":    {avi.VulnType, "Déni de service à distance"},
		"Remediation": {avi.Remediation, "Se référer au bulletin de l'éditeur."},
		"URL":         {avi.URL, srv.URL + "/avis/CERTFR-2026-AVI-0001/"},
		"Published":   {avi.Published.Format("2006-01-02"), "2026-09-01"},
		"AlerteTitre": {ale.Title, "Alerte : Vulnérabilité dans Ivanti"},
		"AlerteSol":   {ale.Remediation, "Appliquer le correctif."},
	}
	for field, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s: obtenu %q, attendu %q", field, c[0], c[1])
		}
	}
	if !strings.HasPrefix(avi.Summary, "De multiples vulnérabilités ont été découvertes dans F5 NGINX.") ||
		!strings.Contains(avi.Summary, "## Documentation") || strings.Contains(avi.Summary, "<span") {
		t.Errorf("résumé: %q", avi.Summary)
	}
	if avi.AffectedVersions != "• NGINX Plus versions antérieures à R36 P2\n• NGINX Open Source versions 1.29.x antérieures à 1.29.4" {
		t.Errorf("systèmes affectés: %q", avi.AffectedVersions)
	}
	wantRefs := []string{srv.URL + "/avis/CERTFR-2026-AVI-0001/", "https://my.f5.com/manage/s/article/K000", srv.URL + "/avis/CERTFR-2026-AVI-0000/"}
	if strings.Join(avi.References, " ") != strings.Join(wantRefs, " ") {
		t.Errorf("références: %q", avi.References)
	}
	if !strings.HasPrefix(ale.Summary, "Alerte CERT-FR (menace active), en cours.") {
		t.Errorf("résumé d'alerte: %q", ale.Summary)
	}
}

func TestCertfrIncremental(t *testing.T) {
	var hits []string
	srv := certfrServer(t, &hits)
	defer srv.Close()
	c := &certfr{base: srv.URL, client: srv.Client(), days: 365, workers: 2}

	advs, err := c.Fetch(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 0 {
		t.Errorf("rien de révisé depuis maintenant, obtenu %d bulletins", len(advs))
	}
	if !IsIncremental(c) || IsOptional(c) {
		t.Error("certfr doit être incrémentale et collectée par défaut")
	}
}

func TestCertfrTooManyFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/avis/json/" {
			w.Write([]byte(`[{"reference":"X","json_url":"/manquant/","last_revision_date":"` +
				time.Now().Format("2006-01-02T15:04:05.000000") + `"}]`))
			return
		}
		if r.URL.Path == "/alerte/json/" {
			w.Write([]byte(`[]`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := &certfr{base: srv.URL, client: srv.Client(), days: 365, workers: 1}
	if _, err := c.Fetch(context.Background(), time.Time{}); err == nil {
		t.Error("échec de tous les détails non signalé")
	}
}
