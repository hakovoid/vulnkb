package store

import (
	"testing"
	"time"

	"vulnkb/internal/epss"
	"vulnkb/internal/model"
)

func TestEPSS(t *testing.T) {
	st, err := Open(t.TempDir() + "/e.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	day := func(d int) time.Time { return time.Date(2026, 9, d, 0, 0, 0, 0, time.UTC) }
	_, err = st.Upsert([]model.Advisory{
		{ID: "osv:a", Source: "osv", ExternalID: "GHSA-a (CVE-2026-1001)", Title: "très menacé", Severity: "LOW", Published: day(1)},
		{ID: "osv:b", Source: "osv", ExternalID: "GHSA-b (CVE-2026-2002, CVE-2026-3003)", Title: "deux CVE", Severity: "HIGH", Published: day(2)},
		{ID: "osv:c", Source: "osv", ExternalID: "GHSA-c", Title: "sans CVE", Severity: "CRITICAL", Published: day(3)},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = st.ReplaceEPSS([]epss.Score{
		{CVE: "CVE-2026-1001", Score: 0.94, Percentile: 0.999},
		{CVE: "CVE-2026-2002", Score: 0.02, Percentile: 0.80},
		{CVE: "CVE-2026-3003", Score: 0.15, Percentile: 0.95},
	}, day(27))
	if err != nil {
		t.Fatal(err)
	}
	res, _ := st.SearchPageSorted("", SortEPSS, 0, 10)
	if len(res) != 3 || res[0].ID != "osv:a" || res[1].ID != "osv:b" || res[2].ID != "osv:c" {
		t.Fatalf("tri EPSS: %+v", res)
	}
	if res[0].EPSS != 0.94 || res[0].EPSSPercentile != 0.999 || res[1].EPSS != 0.15 || res[2].EPSS != 0 {
		t.Errorf("scores lus: %v/%v, %v, %v", res[0].EPSS, res[0].EPSSPercentile, res[1].EPSS, res[2].EPSS)
	}
	for q, want := range map[string]int{"epss:10": 2, "epss:50+": 1, "epss:0,5": 2, "epss:10 sev:high": 1} {
		if n, _ := st.CountMatches(q); n != want {
			t.Errorf("%q: %d, attendu %d", q, n, want)
		}
	}
	if q := ParseQuery("epss:abc epss:200"); len(q.Invalid) != 2 {
		t.Errorf("filtres invalides non signalés: %+v", q.Invalid)
	}
	// une entrée écrite après coup reçoit son score aussitôt
	st.Upsert([]model.Advisory{{ID: "osv:d", Source: "osv", ExternalID: "GHSA-d (CVE-2026-1001)", Title: "nouvelle"}})
	if res, _ := st.Search("nouvelle", 1); len(res) != 1 || res[0].EPSS != 0.94 {
		t.Errorf("EPSS à l'écriture: %+v", res)
	}
	if n, _ := st.CountEPSS(); n != 3 {
		t.Errorf("CountEPSS: %d", n)
	}
	if d, _ := st.Meta("epss_date"); d == "" {
		t.Error("date EPSS non retenue")
	}
	// nouveau jeu : un score qui disparaît remet l'entrée à zéro
	st.ReplaceEPSS([]epss.Score{{CVE: "CVE-2026-3003", Score: 0.3, Percentile: 0.97}}, day(28))
	if res, _ := st.Search("très menacé", 1); res[0].EPSS != 0 {
		t.Errorf("score non remis à zéro: %v", res[0].EPSS)
	}
}
