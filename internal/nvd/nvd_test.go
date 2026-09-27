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
    "weaknesses": [{"description": [{"value": "CWE-79"}, {"value": "NVD-CWE-Other"}]}, {"description": [{"value": "CWE-79"}, {"value": "CWE-80"}]}]}},
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
	var got []model.CVSS
	if err := Parse(strings.NewReader(feed), func(c model.CVSS) error { got = append(got, c); return nil }); err != nil {
		t.Fatal(err)
	}
	want := []model.CVSS{
		// 3.1 préféré à 4.0, et le score NVD (Primary) à celui de l'émetteur
		{CVE: "CVE-2026-1001", Score: 9.8, Level: model.SevCritical, Version: "3.1",
			Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Source: "nvd@nist.gov", CWE: "CWE-79, CWE-80"},
		// seulement un score 4.0 de l'émetteur : on le prend
		{CVE: "CVE-2026-1002", Score: 7.1, Level: model.SevHigh, Version: "4.0", Vector: "CVSS:4.0/AV:A", Source: "cna@y"},
		// CVSS 2 : la sévérité est hors de cvssData
		{CVE: "CVE-2010-0003", Score: 7.5, Level: model.SevHigh, Version: "2.0", Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P", Source: "nvd@nist.gov"},
		// CVE-2026-1004 sans score et CVE-2026-1005 rejeté : ignorés
	}
	if len(got) != len(want) {
		t.Fatalf("obtenu %d scores: %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("score %d:\n obtenu  %+v\n attendu %+v", i, got[i], want[i])
		}
	}

	if err := Parse(strings.NewReader(`{"format":"x"}`), func(model.CVSS) error { return nil }); err == nil {
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
	if err := Fetch(context.Background(), srv.Client(), srv.URL+"/", "2026", func(model.CVSS) error { n++; return nil }); err != nil || n != 3 {
		t.Fatalf("Fetch: %d scores, %v", n, err)
	}
	if err := Fetch(context.Background(), srv.Client(), srv.URL+"/", "1999", func(model.CVSS) error { return nil }); err == nil {
		t.Error("flux absent : erreur attendue")
	}
}
