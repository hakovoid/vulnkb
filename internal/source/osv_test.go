package source

import (
	"archive/zip"
	"bytes"
	"testing"
	"time"
)

func osvZip(t *testing.T, files map[string]string) *zip.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return zr
}

const ghsa = `{
  "id": "GHSA-vvgc-356p-c3xw",
  "summary": "golang.org/x/net vulnerable to Cross-site Scripting",
  "details": "The tokenizer incorrectly interprets tags...",
  "aliases": ["CVE-2025-22872", "GO-2025-3595"],
  "modified": "2026-09-10T03:50:24Z",
  "published": "2025-04-16T19:22:51Z",
  "database_specific": {"severity": "MODERATE", "cwe_ids": ["CWE-79"]},
  "references": [{"type": "WEB", "url": "https://go.dev/cl/662715"}],
  "affected": [{
    "package": {"name": "golang.org/x/net", "ecosystem": "Go"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.38.0"}]}]
  }]
}`

func TestParseOSVZip(t *testing.T) {
	zr := osvZip(t, map[string]string{
		"GHSA-vvgc-356p-c3xw.json": ghsa,
		// alias de la même faille : doit être écarté
		"GO-2025-3595.json": `{"id": "GO-2025-3595", "aliases": ["CVE-2025-22872", "GHSA-vvgc-356p-c3xw"]}`,
		"MAL-2025-1.json":   `{"id": "MAL-2025-1", "summary": "Malicious code in evil"}`,
		"GHSA-old.json":     `{"id": "GHSA-old", "withdrawn": "2025-01-01T00:00:00Z"}`,
		"PYSEC-1.json": `{"id": "PYSEC-1", "details": "Line one\nline two",
			"affected": [{"package": {"name": "lib", "ecosystem": "PyPI"},
			"ranges": [{"events": [{"introduced": "1.0"}, {"last_affected": "1.4"}]}]}]}`,
	})

	advs, err := parseOSVZip(zr, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 2 {
		t.Fatalf("attendu 2 entrées, obtenu %d: %+v", len(advs), advs)
	}

	a := advs[0]
	checks := map[string][2]string{
		"ID":          {a.ID, "osv:GHSA-vvgc-356p-c3xw"},
		"ExternalID":  {a.ExternalID, "GHSA-vvgc-356p-c3xw (CVE-2025-22872, GO-2025-3595)"},
		"Component":   {a.Component, "Go golang.org/x/net"},
		"VulnType":    {a.VulnType, "CWE-79"},
		"Severity":    {a.Severity, "MODERATE"},
		"Affected":    {a.AffectedVersions, "golang.org/x/net < 0.38.0"},
		"Fixed":       {a.FixedVersions, "golang.org/x/net 0.38.0"},
		"Remédiation": {a.Remediation, "Mettre à jour golang.org/x/net en 0.38.0 ou plus."},
		"URL":         {a.URL, "https://osv.dev/vulnerability/GHSA-vvgc-356p-c3xw"},
	}
	for field, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s: obtenu %q, attendu %q", field, c[0], c[1])
		}
	}
	if len(a.References) != 1 || a.Published.Year() != 2025 {
		t.Errorf("références/date: %+v", a)
	}

	b := advs[1]
	if b.Title != "Line one" || b.AffectedVersions != "lib >= 1.0 <= 1.4" || b.Remediation != "" {
		t.Errorf("entrée PYSEC mal convertie: %+v", b)
	}
}

func TestParseOSVZipSince(t *testing.T) {
	zr := osvZip(t, map[string]string{"GHSA-vvgc-356p-c3xw.json": ghsa})
	advs, err := parseOSVZip(zr, time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 0 {
		t.Errorf("entrée modifiée avant since conservée: %+v", advs)
	}
}
