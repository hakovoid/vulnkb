package nvd

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vulnkb/internal/model"
)

const feed = `{
 "resultsPerPage": 5, "format": "NVD_CVE", "version": "2.0",
 "vulnerabilities": [
  {"cve": {"id": "CVE-2026-1001", "vulnStatus": "Analyzed",
    "metrics": {
      "cvssMetricV40": [{"source": "cna@x", "type": "Secondary", "cvssData": {"version": "4.0", "vectorString": "CVSS:4.0/AV:N", "baseScore": 9.3, "baseSeverity": "CRITICAL"}}],
      "cvssMetricV31": [
        {"source": "cna@x", "type": "Secondary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:L", "baseScore": 5.5, "baseSeverity": "MEDIUM"}},
        {"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
    "weaknesses": [{"description": [{"value": "CWE-79"}, {"value": "NVD-CWE-Other"}]}, {"description": [{"value": "CWE-79"}, {"value": "CWE-80"}]}],
    "published": "2024-08-16T17:15:15.153",
    "descriptions": [{"lang": "es", "value": "Descripción"}, {"lang": "en", "value": "VTiger CRM <= 8.1.0 does not properly sanitize user input. It leads to SQL injection."}],
    "configurations": [{"nodes": [{"cpeMatch": [
      {"vulnerable": true, "criteria": "cpe:2.3:a:vtiger:vtiger_crm:*:*:*:*:*:*:*:*", "versionEndIncluding": "8.1.0"},
      {"vulnerable": true, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", "versionStartIncluding": "2.0", "versionEndExcluding": "2.4.1"},
      {"vulnerable": true, "criteria": "cpe:2.3:a:acme:widget:1.9:*:*:*:*:*:*:*"},
      {"vulnerable": false, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}]}]}],
    "references": [{"url": "https://www.shielder.com/advisories/vtiger-sqli/", "tags": ["Exploit", "Third Party Advisory"]}, {"url": "https://vendor.test/fix"}]}},
  {"cve": {"id": "CVE-2026-1002", "vulnStatus": "Received",
    "metrics": {"cvssMetricV40": [{"source": "cna@y", "type": "Secondary", "cvssData": {"version": "4.0", "vectorString": "CVSS:4.0/AV:A", "baseScore": 7.1, "baseSeverity": "HIGH"}}]}}},
  {"cve": {"id": "CVE-2010-0003", "vulnStatus": "Analyzed",
    "metrics": {"cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary", "baseSeverity": "HIGH", "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P", "baseScore": 7.5}}]}}},
  {"cve": {"id": "CVE-2026-1004", "vulnStatus": "Awaiting Analysis", "metrics": {}}},
  {"cve": {"id": "CVE-2026-1005", "vulnStatus": "Rejected",
    "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "baseScore": 10, "baseSeverity": "CRITICAL"}}]}}}
 ],
 "timestamp": "2026-09-27T12:00:00"
}`

func TestParse(t *testing.T) {
	var got []Record
	if err := Parse(strings.NewReader(feed), func(r Record) error { got = append(got, r); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("obtenu %d enregistrements", len(got))
	}
	wantScores := []model.CVSS{
		// 3.1 préféré à 4.0, et le score NVD (Primary) à celui de l'émetteur
		{CVE: "CVE-2026-1001", Score: 9.8, Level: model.SevCritical, Version: "3.1",
			Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Source: "nvd@nist.gov", CWE: "CWE-79, CWE-80"},
		// seulement un score 4.0 de l'émetteur : on le prend
		{CVE: "CVE-2026-1002", Score: 7.1, Level: model.SevHigh, Version: "4.0", Vector: "CVSS:4.0/AV:A", Source: "cna@y"},
		// CVSS 2 : la sévérité est hors de cvssData
		{CVE: "CVE-2010-0003", Score: 7.5, Level: model.SevHigh, Version: "2.0", Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P", Source: "nvd@nist.gov"},
		{}, // pas encore évalué
		{}, // rejeté
	}
	for i, w := range wantScores {
		if got[i].Score != w {
			t.Errorf("score %d:\n obtenu  %+v\n attendu %+v", i, got[i].Score, w)
		}
	}
	if !got[4].Rejected || got[4].Advisory.ID != "" || got[3].Rejected || got[3].Advisory.ID != "nvd:CVE-2026-1004" {
		t.Errorf("rejet mal signalé: %+v / %+v", got[3], got[4])
	}

	a := got[0].Advisory
	checks := map[string][2]string{
		"ID":        {a.ID, "nvd:CVE-2026-1001"},
		"Source":    {a.Source, "nvd"},
		"Titre":     {a.Title, "VTiger CRM <= 8.1.0 does not properly sanitize user input"},
		"Résumé":    {a.Summary, "VTiger CRM <= 8.1.0 does not properly sanitize user input. It leads to SQL injection."},
		"Composant": {a.Component, "vtiger crm, acme widget"},
		"Affectées": {a.AffectedVersions, "vtiger crm <= 8.1.0 ; acme widget >= 2.0 < 2.4.1 ; acme widget = 1.9"},
		"Corrigé":   {a.FixedVersions, "acme widget 2.4.1"},
		"Type":      {a.VulnType, "CWE-79, CWE-80"},
		"Sévérité":  {a.Severity, "CRITICAL"},
		"Publié":    {a.Published.Format("2006-01-02"), "2024-08-16"},
		"URL":       {a.URL, "https://nvd.nist.gov/vuln/detail/CVE-2026-1001"},
	}
	for field, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s: obtenu %q, attendu %q", field, c[0], c[1])
		}
	}
	if len(a.References) != 3 || a.References[0] != a.URL {
		t.Errorf("références: %q", a.References)
	}
	if len(got[0].ExploitRefs) != 1 || got[0].ExploitRefs[0] != "https://www.shielder.com/advisories/vtiger-sqli/" {
		t.Errorf("références d'exploit: %q", got[0].ExploitRefs)
	}
	if got[3].Advisory.Title != "CVE-2026-1004" || got[3].Advisory.Severity != "" {
		t.Errorf("CVE sans description ni score: %+v", got[3].Advisory)
	}

	if err := Parse(strings.NewReader(`{"format":"x"}`), func(Record) error { return nil }); err == nil {
		t.Error("flux sans « vulnerabilities » accepté")
	}
}

func TestFetchGzip(t *testing.T) {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write([]byte(feed))
	w.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nvdcve-2.0-2026.json.gz" {
			http.NotFound(rw, r)
			return
		}
		rw.Write(gz.Bytes())
	}))
	defer srv.Close()

	n := 0
	if err := Fetch(context.Background(), srv.Client(), srv.URL+"/", "2026", func(Record) error { n++; return nil }); err != nil || n != 5 {
		t.Fatalf("Fetch: %d enregistrements, %v", n, err)
	}
	if err := Fetch(context.Background(), srv.Client(), srv.URL+"/", "1999", func(Record) error { return nil }); err == nil {
		t.Error("flux absent : erreur attendue")
	}
}
