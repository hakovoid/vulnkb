package store

import (
	"testing"
	"time"

	"vulnkb/internal/euvd"
	"vulnkb/internal/model"
)

func TestEUVD(t *testing.T) {
	st, err := Open(t.TempDir() + "/e.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.Upsert([]model.Advisory{
		{ID: "nvd:CVE-2026-7001", Source: "nvd", ExternalID: "CVE-2026-7001", Title: "RouterOS SSH"},
		{ID: "nvd:CVE-2026-7002", Source: "nvd", ExternalID: "CVE-2026-7002", Title: "autre"},
	})
	since := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	// une fiche exploitée selon l'ENISA, une simple fiche mise à jour
	if err := st.ReplaceEUVDExploited([]euvd.Record{{ID: "EUVD-2026-72027", CVEs: []string{"CVE-2026-7001"}, ExploitedSince: since}}); err != nil {
		t.Fatal(err)
	}
	st.UpsertEUVD([]euvd.Record{
		{ID: "EUVD-2026-72027", CVEs: []string{"CVE-2026-7001"}}, // sans le marqueur : il reste
		{ID: "EUVD-2026-80000", CVEs: []string{"CVE-2026-7002"}},
	})
	st.RefreshDerived()

	if n, _ := st.CountMatches("exploitee"); n != 1 {
		t.Errorf("exploitées : %d, attendu 1", n)
	}
	got, _ := st.Search("EUVD-2026-72027", 5)
	if len(got) != 1 || got[0].ID != "nvd:CVE-2026-7001" || !got[0].Exploited {
		t.Errorf("recherche par identifiant EUVD : %+v", got)
	}
	refs, _ := st.EUVDFor([]string{"CVE-2026-7001"})
	if len(refs) != 1 || refs[0].ID != "EUVD-2026-72027" || !refs[0].ExploitedSince.Equal(since) {
		t.Errorf("EUVDFor : %+v", refs)
	}
	if ids, expl, _ := st.CountEUVD(); ids != 2 || expl != 1 {
		t.Errorf("comptes : %d identifiants, %d exploitées", ids, expl)
	}
	// sortie de la liste de l'ENISA : le marqueur tombe
	st.ReplaceEUVDExploited(nil)
	st.RefreshDerived()
	if n, _ := st.CountMatches("exploitee"); n != 0 {
		t.Errorf("après retrait de la liste : %d exploitées", n)
	}
	// une fiche écrite après coup reçoit directement le marqueur
	st.ReplaceEUVDExploited([]euvd.Record{{ID: "EUVD-2026-80000", CVEs: []string{"CVE-2026-7002"}, ExploitedSince: since}})
	st.Upsert([]model.Advisory{{ID: "nvd:CVE-2026-7002", Source: "nvd", ExternalID: "CVE-2026-7002", Title: "autre"}})
	if got, _ := st.Search("CVE-2026-7002", 1); len(got) != 1 || !got[0].Exploited {
		t.Error("marqueur non posé à l'écriture")
	}
}
