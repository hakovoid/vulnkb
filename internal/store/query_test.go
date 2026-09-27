package store

import (
	"database/sql"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"vulnkb/internal/model"
)

func TestParseQuery(t *testing.T) {
	cases := []struct {
		in   string
		want Query
	}{
		{"nginx dos", Query{Text: "nginx dos"}},
		{"nginx sev:crit", Query{Text: "nginx", Severities: []int{4}}},
		{"sev:high+ src:KEV,fr", Query{Severities: []int{4, 3}, Sources: []string{"certfr", "cisa-kev"}}},
		{"sévérité:élevée Exploitée", Query{Severities: []int{3}, Exploited: true}},
		{"sev:moyenne,low src:osv", Query{Severities: []int{2, 1}, Sources: []string{"osv"}}},
		{"sev:huge src:x CVE-2026-1001", Query{Text: "CVE-2026-1001", Invalid: []string{"sev:huge", "src:x"}}},
		{"golang.org/x/net http://a", Query{Text: "golang.org/x/net http://a"}},
	}
	for _, c := range cases {
		if got := ParseQuery(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseQuery(%q)\n obtenu  %+v\n attendu %+v", c.in, got, c.want)
		}
	}
}

func TestFilters(t *testing.T) {
	st, err := Open(t.TempDir() + "/f.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	day := func(d int) time.Time { return time.Date(2026, 9, d, 0, 0, 0, 0, time.UTC) }
	_, err = st.Upsert([]model.Advisory{
		{ID: "cisa-kev:CVE-2026-1001", Source: "cisa-kev", ExternalID: "CVE-2026-1001", Title: "Gitea injection", Severity: "Known Exploited", Published: day(1)},
		{ID: "osv:GHSA-a", Source: "osv", ExternalID: "GHSA-a (CVE-2026-1001)", Title: "Gitea RCE", Severity: "CRITICAL",
			FixedVersions: "gitea.dev 1.27.1", Remediation: "Mettre à jour gitea.dev en 1.27.1 ou plus.", Published: day(2)},
		{ID: "osv:GHSA-b", Source: "osv", ExternalID: "GHSA-b (CVE-2026-2002)", Title: "Nginx DoS", Severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", Published: day(3)},
		{ID: "osv:GHSA-c", Source: "osv", ExternalID: "GHSA-c", Title: "Minor leak", Severity: "LOW", Published: day(4)},
		{ID: "certfr:CERTFR-2026-AVI-1", Source: "certfr", ExternalID: "CERTFR-2026-AVI-1 (CVE-2026-1001, CVE-2026-9009)", Title: "Vulnérabilité dans Gitea",
			AffectedVersions: "• Gitea versions antérieures à 1.27.1", Published: day(5)},
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]string{
		"":                  {"CERTFR-2026-AVI-1", "GHSA-c", "GHSA-b", "GHSA-a", "CVE-2026-1001"},
		"sev:crit":          {"GHSA-a"},
		"sev:high+":         {"GHSA-b", "GHSA-a"}, // GHSA-b : vecteur CVSS 7.5
		"sev:inconnue":      {"CERTFR-2026-AVI-1", "CVE-2026-1001"},
		"src:osv sev:low":   {"GHSA-c"},
		"src:kev,fr":        {"CERTFR-2026-AVI-1", "CVE-2026-1001"},
		"exploitee":         {"CERTFR-2026-AVI-1", "GHSA-a", "CVE-2026-1001"},
		"exploitee src:osv": {"GHSA-a"},
		"gitea exploitee":   nil, // ordre de pertinence : on ne vérifie que le nombre
		"1.27.1":            nil, // versions et remédiation désormais indexées
		"mettre jour":       {"GHSA-a"},
		"nginx sev:crit":    {},
		"gitea src:fr":      {"CERTFR-2026-AVI-1"},
	}
	counts := map[string]int{"gitea exploitee": 3, "1.27.1": 2}
	for q, want := range cases {
		res, err := st.Search(q, 50)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		n, err := st.CountMatches(q)
		if err != nil {
			t.Fatalf("count %q: %v", q, err)
		}
		if n != len(res) {
			t.Errorf("%q: CountMatches %d ≠ %d résultats", q, n, len(res))
		}
		if want == nil {
			if len(res) != counts[q] {
				t.Errorf("%q: %d résultats, attendu %d", q, len(res), counts[q])
			}
			continue
		}
		var got []string
		for _, a := range res {
			got = append(got, primaryIDForTest(a.ExternalID))
		}
		if len(got) != len(want) || (len(want) > 0 && !reflect.DeepEqual(got, want)) {
			t.Errorf("%q: obtenu %v, attendu %v", q, got, want)
		}
	}
}

func TestNVDScores(t *testing.T) {
	st, err := Open(t.TempDir() + "/nvd.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, err = st.Upsert([]model.Advisory{
		{ID: "cisa-kev:CVE-2026-1001", Source: "cisa-kev", ExternalID: "CVE-2026-1001", Title: "kev", Severity: "Known Exploited"},
		{ID: "certfr:A", Source: "certfr", ExternalID: "CERTFR-2026-AVI-1 (CVE-2026-1001, CVE-2026-2002)", Title: "fr"},
		{ID: "osv:B", Source: "osv", ExternalID: "GHSA-b (CVE-2026-2002)", Title: "osv", Severity: "LOW"},
		{ID: "certfr:C", Source: "certfr", ExternalID: "CERTFR-2026-AVI-2", Title: "fr sans cve"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNVD([]model.CVSS{
		{CVE: "CVE-2026-1001", Score: 9.8, Level: model.SevCritical, Version: "3.1", Vector: "CVSS:3.1/AV:N", Source: "nvd@nist.gov", CWE: "CWE-79"},
		{CVE: "CVE-2026-2002", Score: 7.5, Level: model.SevHigh, Version: "4.0", Source: "cna@x"},
	}); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.CountMatches("sev:crit"); n != 0 {
		t.Errorf("sévérité NVD prise en compte avant RefreshLevels: %d", n)
	}
	if err := st.RefreshLevels(); err != nil {
		t.Fatal(err)
	}

	for q, want := range map[string]int{
		"sev:crit":     2, // KEV et l'avis CERT-FR via le CVE le plus grave
		"sev:high":     0, // l'entrée OSV garde sa propre sévérité (LOW)
		"sev:low":      1,
		"sev:inconnue": 1, // l'avis sans CVE
	} {
		if n, err := st.CountMatches(q); err != nil || n != want {
			t.Errorf("%q: %d (%v), attendu %d", q, n, err, want)
		}
	}

	res, _ := st.Search("src:fr", 10)
	if len(res) != 2 {
		t.Fatalf("src:fr: %d résultats", len(res))
	}
	for _, a := range res {
		switch a.ID {
		case "certfr:A":
			want := model.CVSS{CVE: "CVE-2026-1001", Score: 9.8, Level: model.SevCritical, Version: "3.1", Vector: "CVSS:3.1/AV:N", Source: "nvd@nist.gov", CWE: "CWE-79"}
			if a.NVD != want {
				t.Errorf("meilleur score NVD:\n obtenu  %+v\n attendu %+v", a.NVD, want)
			}
		case "certfr:C":
			if a.NVD != (model.CVSS{}) {
				t.Errorf("score NVD inattendu: %+v", a.NVD)
			}
		}
	}

	if n, _ := st.CountNVD(); n != 2 {
		t.Errorf("CountNVD: %d", n)
	}
	if v, _ := st.Meta("x"); v != "" {
		t.Errorf("meta absente: %q", v)
	}
	st.SetMeta("x", "1")
	st.SetMeta("x", "2")
	if v, _ := st.Meta("x"); v != "2" {
		t.Errorf("meta: %q", v)
	}
}

func primaryIDForTest(ext string) string {
	for i := range ext {
		if ext[i] == ' ' {
			return ext[:i]
		}
	}
	return ext
}

// TestMigrateOldSchema ouvre une base au schéma de la première version
// (index plein-texte sur 5 colonnes, sans niveau de sévérité ni table des
// CVE) et vérifie qu'elle est mise à niveau sans perte.
func TestMigrateOldSchema(t *testing.T) {
	path := t.TempDir() + "/v1.db"
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE advisories (
    id TEXT PRIMARY KEY, source TEXT NOT NULL, external_id TEXT, title TEXT, summary TEXT,
    component TEXT, vuln_type TEXT, severity TEXT, affected_versions TEXT, fixed_versions TEXT,
    references_json TEXT, published INTEGER, fetched INTEGER, url TEXT);
CREATE VIRTUAL TABLE advisories_fts USING fts5(external_id, title, summary, component, vuln_type,
    content='advisories', content_rowid='rowid');
CREATE TRIGGER advisories_ai AFTER INSERT ON advisories BEGIN
    INSERT INTO advisories_fts(rowid, external_id, title, summary, component, vuln_type)
    VALUES (new.rowid, new.external_id, new.title, new.summary, new.component, new.vuln_type);
END;
INSERT INTO advisories (id, source, external_id, title, summary, component, vuln_type, severity,
    affected_versions, fixed_versions, references_json, published, fetched, url)
VALUES ('osv:GHSA-z', 'osv', 'GHSA-z (CVE-2026-7007)', 'Old entry', 's', 'c', 'CWE-79', 'HIGH',
    '', 'lib 4.5.6', '', 0, 0, ''),
       ('cisa-kev:CVE-2026-7007', 'cisa-kev', 'CVE-2026-7007', 'Kev entry', '', '', '', 'Known Exploited',
    '', '', '', 0, 0, '');`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("migration: %v", err)
	}
	defer st.Close()
	for q, want := range map[string]int{"4.5.6": 1, "old": 1, "sev:high": 1, "exploitee src:osv": 1} {
		if n, err := st.CountMatches(q); err != nil || n != want {
			t.Errorf("%q après migration: %d (%v), attendu %d", q, n, err, want)
		}
	}
	var au string
	st.db.QueryRow(`SELECT sql FROM sqlite_master WHERE name = 'advisories_au'`).Scan(&au)
	if !strings.Contains(au, "UPDATE OF") {
		t.Errorf("trigger de mise à jour non restreint aux colonnes indexées: %s", au)
	}
	if n, _ := st.CountMatches("sev:high src:osv"); n != 1 {
		t.Errorf("eff_level non calculé à la migration: %d", n)
	}
	// une seconde ouverture ne doit rien reconstruire ni casser
	st.Close()
	if st, err = Open(path); err != nil {
		t.Fatalf("réouverture: %v", err)
	}
	if n, _ := st.CountMatches("4.5.6"); n != 1 {
		t.Errorf("réouverture: %d", n)
	}
}

func TestNVDShadowing(t *testing.T) {
	st, err := Open(t.TempDir() + "/shadow.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, err = st.Upsert([]model.Advisory{
		{ID: "nvd:CVE-2026-1001", Source: "nvd", ExternalID: "CVE-2026-1001", Title: "gitea nvd"},
		{ID: "nvd:CVE-2026-2002", Source: "nvd", ExternalID: "CVE-2026-2002", Title: "vtiger nvd"},
		{ID: "nvd:CVE-2026-3003", Source: "nvd", ExternalID: "CVE-2026-3003", Title: "kernel nvd"},
		{ID: "osv:GHSA-a", Source: "osv", ExternalID: "GHSA-a (CVE-2026-1001)", Title: "gitea osv"},
		{ID: "certfr:X", Source: "certfr", ExternalID: "CERTFR-2026-AVI-9 (CVE-2026-3003)", Title: "kernel fr"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RefreshDerived(); err != nil {
		t.Fatal(err)
	}
	for q, want := range map[string]int{
		"":        4, // l'entrée NVD de CVE-2026-1001 est masquée (fiche OSV)
		"gitea":   1,
		"vtiger":  1,
		"kernel":  2, // un avis CERT-FR ne masque pas l'entrée NVD
		"src:nvd": 3, // demandé explicitement : tout NVD
	} {
		if n, err := st.CountMatches(q); err != nil || n != want {
			t.Errorf("%q: %d (%v), attendu %d", q, n, err, want)
		}
	}

	// la fiche OSV disparaît : l'entrée NVD redevient visible
	if err := st.DeleteAdvisories([]string{"osv:GHSA-a"}); err != nil {
		t.Fatal(err)
	}
	st.RefreshDerived()
	if n, _ := st.CountMatches("gitea"); n != 1 {
		t.Errorf("entrée NVD non démasquée: %d", n)
	}
	if res, _ := st.Search("gitea", 5); len(res) != 1 || res[0].Source != "nvd" {
		t.Errorf("gitea après suppression: %+v", res)
	}
}

func TestWatchFilter(t *testing.T) {
	st, err := Open(t.TempDir() + "/w.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, err = st.Upsert([]model.Advisory{
		{ID: "osv:1", Source: "osv", ExternalID: "GHSA-a (CVE-2026-1)", Title: "Nginx DoS", Component: "Go nginx-ui", Severity: "HIGH"},
		{ID: "osv:2", Source: "osv", ExternalID: "GHSA-b", Title: "SQL injection", Component: "PyPI vtiger-connector", Severity: "CRITICAL"},
		{ID: "osv:3", Source: "osv", ExternalID: "GHSA-c", Title: "XSS in Wordpress", Component: "wordpress", Severity: "MEDIUM"},
		{ID: "certfr:X", Source: "certfr", ExternalID: "CERTFR-2026-AVI-1", Title: "Vulnérabilité dans F5 NGINX", Component: "F5 NGINX"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// liste vide : « mes » ne renvoie rien
	SetWatchlist(nil)
	if q := ParseQuery("mes"); !q.Impossible() {
		t.Error("mes sans liste devrait être impossible")
	}
	if n, _ := st.CountMatches("mes"); n != 0 {
		t.Errorf("mes sans liste: %d résultats", n)
	}

	SetWatchlist([]string{"nginx", "vtiger"})
	defer SetWatchlist(nil)
	cases := map[string]int{
		"mes":           3, // les deux nginx + vtiger
		"mes sev:crit":  1, // vtiger uniquement
		"mes src:fr":    1, // l'avis CERT-FR NGINX
		"mes wordpress": 0, // wordpress n'est pas surveillé
		"mes dos":       1, // nginx DoS
	}
	for query, want := range cases {
		n, err := st.CountMatches(query)
		if err != nil {
			t.Fatalf("%q: %v", query, err)
		}
		res, _ := st.Search(query, 50)
		if n != len(res) {
			t.Errorf("%q: count %d ≠ %d résultats", query, n, len(res))
		}
		if n != want {
			t.Errorf("%q: %d résultats, attendu %d", query, n, want)
		}
	}
}

func TestLoadWatchlist(t *testing.T) {
	path := t.TempDir() + "/watch.txt"
	os.WriteFile(path, []byte("# commentaire\nnginx\n\n  vtiger  \n"), 0o644)
	n, err := LoadWatchlist(path)
	if err != nil || n != 2 {
		t.Fatalf("LoadWatchlist: %d (%v)", n, err)
	}
	if got := Watchlist(); len(got) != 2 || got[0] != "nginx" || got[1] != "vtiger" {
		t.Errorf("Watchlist: %q", got)
	}
	if n, err := LoadWatchlist(path + ".absent"); err != nil || n != 0 || len(Watchlist()) != 0 {
		t.Errorf("fichier absent mal géré: %d (%v)", n, err)
	}
}
