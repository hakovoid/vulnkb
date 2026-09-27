package store

import (
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
			Published: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
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
}
