package store

import (
	"testing"
	"time"

	"vulnkb/internal/model"
)

func TestOverviewAndExposure(t *testing.T) {
	st, err := Open(t.TempDir() + "/s.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now()
	st.Upsert([]model.Advisory{
		{ID: "cisa-kev:CVE-2026-1001", Source: "cisa-kev", ExternalID: "CVE-2026-1001", Title: "nginx exploited", Severity: "CRITICAL", Published: now},
		{ID: "osv:a", Source: "osv", ExternalID: "GHSA-a", Title: "Nginx UI flaw", Component: "Go nginx-ui", Severity: "HIGH", VulnType: "CWE-79", Published: now.AddDate(-1, 0, 0)},
		{ID: "osv:b", Source: "osv", ExternalID: "GHSA-b", Title: "express bug", Component: "npm express, express-session", Severity: "CRITICAL", VulnType: "CWE-79, CWE-89", Published: now.AddDate(-2, 0, 0)},
		{ID: "osv:c", Source: "osv", ExternalID: "GHSA-c", Title: "codegen", Component: "npm @x/codegen-express", Severity: "HIGH"},
		{ID: "osv:d", Source: "osv", ExternalID: "GHSA-d", Title: "minor nginx", Component: "nginx", Severity: "LOW"},
	})
	st.RefreshDerived()

	o, err := st.Overview(5, 3)
	if err != nil {
		t.Fatal(err)
	}
	if o.Visible != 5 || o.BySeverity[4] != 2 || o.BySeverity[3] != 2 || o.BySeverity[1] != 1 || o.Exploited != 1 {
		t.Errorf("vue d'ensemble : %+v", o)
	}
	if len(o.TopCWE) != 2 || o.TopCWE[0] != (CWECount{"CWE-79", 2}) {
		t.Errorf("CWE : %+v", o.TopCWE)
	}
	if len(o.ByYear) != 3 || o.Recent30 != 1 {
		t.Errorf("années : %+v, récentes %d", o.ByYear, o.Recent30)
	}

	exp, err := st.ExposureByTerm([]string{"nginx", "npm:express", "npm:inconnu"})
	if err != nil {
		t.Fatal(err)
	}
	want := []TermExposure{{"nginx", 2, 1}, {"npm:express", 1, 0}}
	if len(exp) != 2 || exp[0] != want[0] || exp[1] != want[1] {
		t.Errorf("exposition : %+v", exp)
	}
	// cohérence avec le filtre SQL
	for _, e := range exp {
		n, _ := st.CountWithWatch([]string{e.Term}, "sev:high+")
		if n != e.Severe {
			t.Errorf("%s : %d en mémoire, %d en SQL", e.Term, e.Severe, n)
		}
	}
}
