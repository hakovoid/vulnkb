package store

import (
	"database/sql"
	"reflect"
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
	// une seconde ouverture ne doit rien reconstruire ni casser
	st.Close()
	if st, err = Open(path); err != nil {
		t.Fatalf("réouverture: %v", err)
	}
	if n, _ := st.CountMatches("4.5.6"); n != 1 {
		t.Errorf("réouverture: %d", n)
	}
}
