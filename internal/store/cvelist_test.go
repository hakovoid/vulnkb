package store

import (
	"testing"
	"time"

	"vulnkb/internal/cvelist"
	"vulnkb/internal/model"
)

func TestCVEList(t *testing.T) {
	st, err := Open(t.TempDir() + "/c.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now()
	// une fiche NVD pas encore analysée, une autre complète
	st.Upsert([]model.Advisory{
		{ID: "nvd:CVE-2026-1001", Source: "nvd", ExternalID: "CVE-2026-1001", Title: "Hugo versions 0.75.0 through", Published: now},
		{ID: "nvd:CVE-2026-1002", Source: "nvd", ExternalID: "CVE-2026-1002", Title: "complète", Component: "nginx",
			VulnType: "CWE-787", AffectedVersions: "nginx < 1.2", Published: now},
	})
	st.UpsertNVD([]model.CVSS{{CVE: "CVE-2026-1002", Score: 9.8, Level: 4, Source: "nvd@nist.gov"}})

	wanted, err := st.CVEListFilter()
	if err != nil {
		t.Fatal(err)
	}
	if !wanted("CVE-2026-1001") || wanted("CVE-2026-1002") || !wanted("CVE-2026-9999") {
		t.Error("filtre : seules les fiches incomplètes ou absentes sont utiles")
	}
	recs := []cvelist.Record{
		{CVE: "CVE-2026-1001", Title: "Hugo Stored XSS", Component: "gohugoio hugo", Affected: "gohugoio hugo < 0.166.0",
			Fixed: "gohugoio hugo 0.166.0", CWE: "CWE-79",
			Score: model.CVSS{CVE: "CVE-2026-1001", Score: 8.1, Level: 3, Source: "CNA VulnCheck"},
			SSVC:  cvelist.SSVC{Exploitation: "poc", Automatable: "yes", Impact: "total"}},
		{CVE: "CVE-2026-1002", Title: "autre titre", Component: "autre", SSVC: cvelist.SSVC{Exploitation: "active"}},
	}
	kept, err := st.UpsertCVEList(recs, wanted)
	if err != nil || kept != 1 {
		t.Fatalf("gardées : %d, %v", kept, err)
	}
	if err := st.RefreshDerived(); err != nil {
		t.Fatal(err)
	}

	got, _ := st.Search("hugo", 5)
	if len(got) != 1 {
		t.Fatalf("recherche hugo : %d résultats", len(got))
	}
	a := got[0]
	if a.Title != "Hugo Stored XSS" || a.Component != "gohugoio hugo" || a.FixedVersions != "gohugoio hugo 0.166.0" ||
		a.VulnType != "CWE-79" || a.NVD.Score != 8.1 || !a.HasExploit {
		t.Errorf("fiche complétée : %+v", a)
	}
	if n, _ := st.CountMatches("sev:high exploit"); n != 1 {
		t.Errorf("sévérité et exploit d'après la liste officielle : %d", n)
	}
	// ce que NVD fournit n'est pas remplacé
	full, _ := st.Search("CVE-2026-1002", 1)
	if full[0].Component != "nginx" || full[0].Title != "complète" || full[0].NVD.Score != 9.8 {
		t.Errorf("fiche NVD complète modifiée : %+v", full[0])
	}
	// une synchro NVD réécrit la fiche : les trous sont comblés de nouveau
	st.Upsert([]model.Advisory{{ID: "nvd:CVE-2026-1001", Source: "nvd", ExternalID: "CVE-2026-1001", Title: "Hugo versions", Published: now}})
	st.RefreshDerived()
	if again, _ := st.Search("gohugoio", 1); len(again) != 1 || again[0].Component != "gohugoio hugo" {
		t.Error("fiche non complétée après réécriture")
	}

	v, _ := st.SSVCFor([]string{"CVE-2026-1001", "CVE-2026-1002"})
	if v.Exploitation != "active" {
		t.Errorf("SSVC le plus grave : %+v", v)
	}
	// un CVE rejeté disparaît des deux tables
	st.UpsertCVEList([]cvelist.Record{{CVE: "CVE-2026-1001", Rejected: true}}, wanted)
	if recs, ssvc, _ := st.CountCVEList(); recs != 0 || ssvc != 1 {
		t.Errorf("après rejet : %d fiches, %d SSVC", recs, ssvc)
	}
}
