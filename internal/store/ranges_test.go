package store

import (
	"testing"

	"vulnkb/internal/model"
)

func TestParseWatchTerm(t *testing.T) {
	for raw, want := range map[string]WatchTerm{
		"nginx":                    {Name: "nginx"},
		"npm:axios":                {Ecosystem: "npm", Label: "npm", Package: "axios", Name: "axios"},
		"npm:axios@1.6.0, 1.7.2":   {Ecosystem: "npm", Label: "npm", Package: "axios", Name: "axios", Versions: "1.6.0,1.7.2"},
		"npm:@scope/pkg@2.0.0":     {Ecosystem: "npm", Label: "npm", Package: "@scope/pkg", Name: "@scope/pkg", Versions: "2.0.0"},
		"npm:@scope/pkg":           {Ecosystem: "npm", Label: "npm", Package: "@scope/pkg", Name: "@scope/pkg"},
		"pypi:Pydantic_Settings@2": {Ecosystem: "pypi", Label: "pypi", Package: "pydantic-settings", Name: "Pydantic_Settings", Versions: "2"},
		"crates:serde":             {Ecosystem: "crates", Label: "crates.io", Package: "serde", Name: "serde"},
		"inconnu:truc":             {Name: "inconnu:truc"},
	} {
		got := ParseWatchTerm(raw)
		got.Raw = ""
		if got != want {
			t.Errorf("ParseWatchTerm(%q) = %+v, attendu %+v", raw, got, want)
		}
	}
}

// Le filtre « mes » avec version : seules les fiches qui touchent la
// version utilisée restent ; une fiche sans plage connue reste par prudence.
func TestWatchVersionFilter(t *testing.T) {
	st, err := Open(t.TempDir() + "/r.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rng := func(intro, fixed string) []model.Range {
		return []model.Range{{Ecosystem: "npm", Package: "axios", Introduced: intro, Fixed: fixed}}
	}
	st.Upsert([]model.Advisory{
		{ID: "osv:GHSA-old", Source: "osv", ExternalID: "GHSA-old", Title: "ancienne", Component: "npm axios",
			Severity: "HIGH", Ranges: rng("0", "0.28.0")},
		{ID: "osv:GHSA-hit", Source: "osv", ExternalID: "GHSA-hit", Title: "touche 1.6", Component: "npm axios",
			Severity: "HIGH", Ranges: append(rng("0", "0.30.0"), rng("1.0.0", "1.6.4")...)},
		{ID: "osv:GHSA-unk", Source: "osv", ExternalID: "GHSA-unk", Title: "sans plage", Component: "npm axios", Severity: "HIGH"},
		{ID: "osv:GHSA-other", Source: "osv", ExternalID: "GHSA-other", Title: "autre paquet", Component: "npm axios-retry",
			Severity: "HIGH", Ranges: []model.Range{{Ecosystem: "npm", Package: "axios-retry", Introduced: "0", Fixed: "9"}}},
	})
	defer SetWatchlist(nil)

	count := func(terms ...string) int {
		SetWatchlist(terms)
		n, err := st.CountMatches("mes")
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count("npm:axios"); n != 3 {
		t.Errorf("sans version : %d fiches, attendu 3", n)
	}
	if n := count("npm:axios@1.6.0"); n != 2 { // hit + sans plage
		t.Errorf("axios 1.6.0 : %d fiches, attendu 2", n)
	}
	if n := count("npm:axios@1.7.9"); n != 1 { // sans plage seulement
		t.Errorf("axios 1.7.9 : %d fiches, attendu 1", n)
	}
	if n := count("npm:axios@1.7.9,0.21.1"); n != 3 {
		t.Errorf("deux versions : %d fiches, attendu 3", n)
	}

	SetWatchlist([]string{"npm:axios@1.6.0"})
	hits, err := st.WatchedVersionsHit("osv:GHSA-hit")
	if err != nil || len(hits) != 1 || hits[0].Version != "1.6.0" || hits[0].Fixed != "1.6.4" {
		t.Errorf("versions touchées : %+v, %v", hits, err)
	}
	if hits, _ := st.WatchedVersionsHit("osv:GHSA-old"); len(hits) != 0 {
		t.Errorf("GHSA-old ne touche pas 1.6.0 : %+v", hits)
	}
	// les statistiques suivent la même règle que le filtre
	exp, err := st.ExposureByTerm([]string{"npm:axios@1.6.0"})
	if err != nil || len(exp) != 1 || exp[0].Severe != 2 {
		t.Errorf("exposition : %+v, %v", exp, err)
	}
	// réécrire une fiche OSV sans plage efface les anciennes plages
	st.Upsert([]model.Advisory{{ID: "osv:GHSA-old", Source: "osv", ExternalID: "GHSA-old", Title: "ancienne", Component: "npm axios", Severity: "HIGH"}})
	if n := count("npm:axios@1.7.9"); n != 2 {
		t.Errorf("après réécriture : %d fiches, attendu 2", n)
	}
}
