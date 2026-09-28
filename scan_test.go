package main

import (
	"os"
	"path/filepath"
	"testing"

	"vulnkb/internal/model"
	"vulnkb/internal/store"
)

func TestScanRoot(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/s.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rng := func(pkg, intro, fixed string) []model.Range {
		return []model.Range{{Ecosystem: "pypi", Package: pkg, Introduced: intro, Fixed: fixed}}
	}
	st.Upsert([]model.Advisory{
		{ID: "osv:GHSA-a", Source: "osv", ExternalID: "GHSA-a (CVE-2026-1001)", Title: "DoS", Component: "PyPI python-multipart",
			Severity: "HIGH", Ranges: rng("python-multipart", "0", "0.0.18")},
		{ID: "osv:GHSA-b", Source: "osv", ExternalID: "GHSA-b (CVE-2026-1002)", Title: "écriture de fichier", Component: "PyPI python-multipart",
			Severity: "CRITICAL", Ranges: rng("python-multipart", "0", "0.0.31")},
		{ID: "osv:GHSA-c", Source: "osv", ExternalID: "GHSA-c", Title: "ancienne", Component: "PyPI python-multipart",
			Severity: "HIGH", Ranges: rng("python-multipart", "0", "0.0.7")},
		{ID: "osv:GHSA-d", Source: "osv", ExternalID: "GHSA-d", Title: "faible", Component: "PyPI fastapi",
			Severity: "LOW", Ranges: rng("fastapi", "0", "0.200.0")},
	})

	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "api"), 0o755)
	os.WriteFile(filepath.Join(root, "api", "requirements.txt"),
		[]byte("python-multipart==0.0.9\nfastapi==0.109.2\nhttpx==0.27.0\nuvicorn>=0.29\n"), 0o644)
	os.WriteFile(filepath.Join(root, "docker-compose.yml"), []byte("services:\n  r:\n    image: redis:7\n"), 0o644)

	files, err := scanRoot(st, root, scanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var api, compose fileResult
	for _, f := range files {
		switch f.File {
		case filepath.Join("api", "requirements.txt"):
			api = f
		case "docker-compose.yml":
			compose = f
		}
	}
	if len(api.Vulnerable) != 2 || api.Clean != 1 || len(api.Unknown) != 1 || api.Unknown[0] != "uvicorn" {
		t.Fatalf("bilan : %+v", api)
	}
	pm := api.Vulnerable[0] // la plus grave d'abord
	if pm.Term.Name != "python-multipart" || len(pm.Vulns) != 2 || pm.Target != "0.0.31" ||
		pm.Vulns[0].Level != model.SevCritical || pm.Vulns[0].Fixed != "0.0.31" {
		t.Errorf("python-multipart : %+v", pm)
	}
	if len(compose.Images) != 1 || compose.Images[0] != "redis" {
		t.Errorf("images : %+v", compose)
	}
	// seuil d'affichage : la faille faible de fastapi disparaît
	files, _ = scanRoot(st, root, scanOptions{Min: model.SevMedium})
	for _, f := range files {
		if f.File == filepath.Join("api", "requirements.txt") && (len(f.Vulnerable) != 1 || f.Clean != 2) {
			t.Errorf("avec -min med : %+v", f)
		}
	}
}

func TestParseLevel(t *testing.T) {
	for s, want := range map[string]int{"crit": 4, "Élevée": 3, "high": 3, "med": 2, "faible": 1, "all": 0, "none": 5} {
		if got, err := parseLevel(s); err != nil || got != want {
			t.Errorf("parseLevel(%q) = %d, %v", s, got, err)
		}
	}
	if _, err := parseLevel("grave"); err == nil {
		t.Error("seuil inconnu accepté")
	}
}
