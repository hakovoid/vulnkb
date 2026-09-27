package store

import (
	"database/sql"
	"testing"
	"time"

	"vulnkb/internal/model"
)

func TestUpsertAndSearch(t *testing.T) {
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	seed := []model.Advisory{
		{
			ID: "blog:hacktron-openai", Source: "blog", ExternalID: "HEIF-Heist",
			Title:     "Heap overflow in libheif chained to OpenAI SSO takeover",
			Summary:   "A heap buffer overflow in libheif via HEIC image upload, chained with an OpenAI SSO misconfiguration, led to internal repo access.",
			Component: "libheif", VulnType: "heap overflow", Severity: "Critical",
			AffectedVersions: "1.19.7, 1.19.8", FixedVersions: "1.23.4",
			References: []string{"https://www.hacktron.ai/blog/hacking-openai"},
			Published:  time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC),
		},
		{
			ID: "cisa-kev:CVE-2026-0001", Source: "cisa-kev", ExternalID: "CVE-2026-0001",
			Title: "Pre-auth RCE in ExampleVPN", Summary: "Remote code execution before authentication.",
			Component: "ExampleVPN", VulnType: "RCE", Severity: "Known Exploited",
			Remediation: "Apply mitigations per vendor instructions.",
			Published:   time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	n, err := st.Upsert(seed)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("upsert: attendu 2, obtenu %d", n)
	}

	// idempotence : réinsérer ne duplique pas
	if _, err := st.Upsert(seed); err != nil {
		t.Fatal(err)
	}
	if c, _ := st.Count(); c != 2 {
		t.Fatalf("count après ré-upsert: attendu 2, obtenu %d", c)
	}

	cases := []struct {
		query string
		want  int
	}{
		{"libheif", 1},
		{"heap", 1},
		{"RCE", 1},
		{"CVE-2026-0001", 1}, // caractères spéciaux dans la requête FTS
		{"nonexistent", 0},
		{"", 2}, // requête vide = tout, trié par date
	}
	for _, c := range cases {
		res, err := st.Search(c.query, 50)
		if err != nil {
			t.Fatalf("search %q: %v", c.query, err)
		}
		if len(res) != c.want {
			t.Errorf("search %q: attendu %d, obtenu %d", c.query, c.want, len(res))
		}
	}

	// la requête vide doit trier par date décroissante
	res, _ := st.Search("", 50)
	if len(res) == 2 && res[0].Published.Before(res[1].Published) {
		t.Error("tri par date décroissante attendu")
	}

	// les références font l'aller-retour
	res, _ = st.Search("libheif", 1)
	if len(res) != 1 || len(res[0].References) != 1 || res[0].FixedVersions != "1.23.4" {
		t.Errorf("champs mal restitués: %+v", res)
	}

	res, _ = st.Search("ExampleVPN", 1)
	if len(res) != 1 || res[0].Remediation != "Apply mitigations per vendor instructions." {
		t.Errorf("remédiation mal restituée: %+v", res)
	}
}

func TestCVEIndex(t *testing.T) {
	st, err := Open(t.TempDir() + "/idx.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, err = st.Upsert([]model.Advisory{
		{ID: "certfr:A", Source: "certfr", ExternalID: "CERTFR-2026-AVI-1 (CVE-2026-1111, CVE-2026-2222)", Title: "Avis A", URL: "https://a"},
		{ID: "certfr:B", Source: "certfr", ExternalID: "CERTFR-2026-AVI-2 (CVE-2026-1111)", Title: "Avis B"},
		{ID: "osv:X", Source: "osv", ExternalID: "GHSA-x (CVE-2026-3333)"},
	})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := st.CVEIndex("certfr")
	if err != nil {
		t.Fatal(err)
	}
	if len(idx) != 2 || len(idx["CVE-2026-1111"]) != 2 || idx["CVE-2026-2222"][0] != (Ref{"CERTFR-2026-AVI-1", "Avis A", "https://a"}) {
		t.Errorf("index: %+v", idx)
	}
	if _, ok := idx["CVE-2026-3333"]; ok {
		t.Error("CVE d'une autre source indexé")
	}
}

func TestMigrateAddsRemediation(t *testing.T) {
	path := t.TempDir() + "/old.db"
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE advisories (
		id TEXT PRIMARY KEY, source TEXT NOT NULL, external_id TEXT, title TEXT,
		summary TEXT, component TEXT, vuln_type TEXT, severity TEXT,
		affected_versions TEXT, fixed_versions TEXT, references_json TEXT,
		published INTEGER, fetched INTEGER, url TEXT);
	INSERT INTO advisories (id, source, external_id, title, summary, component, vuln_type,
		severity, affected_versions, fixed_versions, references_json, published, fetched, url)
	VALUES ('x:1', 'x', 'CVE-1', 't', 's', 'c', 'v', 'sev', '', '', '', 0, 0, '');`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("ouverture d'une base sans colonne remediation: %v", err)
	}
	defer st.Close()
	res, err := st.Search("", 10)
	if err != nil || len(res) != 1 || res[0].Remediation != "" {
		t.Fatalf("lecture après migration: %v %+v", err, res)
	}
}
