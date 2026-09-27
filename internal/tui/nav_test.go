package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"vulnkb/internal/model"
	"vulnkb/internal/store"
)

// navUI prépare une interface sur n entrées publiées un jour d'écart : le
// rang k (0 = plus récente) correspond à l'entrée « E<n-1-k> ».
func navUI(t *testing.T, n int) *ui {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/nav.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	var advs []model.Advisory
	for i := 0; i < n; i++ {
		title := "entrée banale"
		if i%10 == 0 {
			title = "entrée spéciale"
		}
		advs = append(advs, model.Advisory{
			ID: fmt.Sprintf("t:%d", i), Source: "osv", ExternalID: fmt.Sprintf("E%d", i),
			Title: title, Published: base.AddDate(0, 0, i),
		})
	}
	if _, err := st.Upsert(advs); err != nil {
		t.Fatal(err)
	}
	u := &ui{st: st, rows: 30, cols: 100, listH: 12, detH: 12}
	u.total, _ = st.Count()
	u.reload()
	return u
}

func selected(t *testing.T, u *ui) string {
	t.Helper()
	a, ok := u.current()
	if !ok {
		t.Fatalf("aucune entrée sélectionnée (curseur %d, fenêtre %d+%d)", u.cursor, u.offset, len(u.results))
	}
	return a.ExternalID
}

func press(u *ui, keys ...string) {
	for _, k := range keys {
		u.handle([]byte(k))
	}
}

func TestGotoAndJumps(t *testing.T) {
	u := navUI(t, 500)
	if u.matches != 500 || len(u.results) != window {
		t.Fatalf("chargement initial: %d résultats, %d en mémoire", u.matches, len(u.results))
	}

	press(u, "\x07", "4", "5", "x", "6", "\r") // Ctrl-G 456 (le x est ignoré)
	if u.cursor != 455 || selected(t, u) != "E44" || u.gotoMode {
		t.Errorf("Ctrl-G 456: curseur %d, entrée %s", u.cursor, selected(t, u))
	}
	if u.top > u.cursor || u.cursor >= u.top+u.listH {
		t.Errorf("sélection hors écran: top %d, curseur %d", u.top, u.cursor)
	}

	press(u, "\x1b[F") // Fin
	if u.cursor != 499 || selected(t, u) != "E0" {
		t.Errorf("Fin: curseur %d", u.cursor)
	}
	press(u, "\x1b[H", "\x1b[6~") // Début puis PgDn
	if u.cursor != u.listH-1 || selected(t, u) != fmt.Sprintf("E%d", 499-(u.listH-1)) {
		t.Errorf("PgDn: curseur %d", u.cursor)
	}
	press(u, "\x07", "9", "9", "9", "9", "\r") // au-delà du dernier : borné
	if u.cursor != 499 {
		t.Errorf("Ctrl-G trop grand: curseur %d", u.cursor)
	}
	press(u, "\x07", "1", "\x1b") // Esc annule
	if u.cursor != 499 || u.gotoMode {
		t.Errorf("Esc n'annule pas: curseur %d", u.cursor)
	}
}

func TestSearchResetsPosition(t *testing.T) {
	u := navUI(t, 500)
	press(u, "\x1b[F")
	press(u, "s", "p", "é", "c", "i", "a", "l", "e")
	if u.matches != 50 || u.cursor != 0 {
		t.Fatalf("recherche: %d résultats, curseur %d", u.matches, u.cursor)
	}
	press(u, "\x1b[F")
	if u.cursor != 49 || !strings.HasPrefix(selected(t, u), "E") {
		t.Errorf("Fin sur recherche: curseur %d", u.cursor)
	}
}

func TestRenderShowsPosition(t *testing.T) {
	u := navUI(t, 500)
	press(u, "\x07", "2", "3", "4", "\r")
	var b strings.Builder
	u.listH = 12
	u.renderList(&b, u.listH)
	if !strings.Contains(b.String(), "E266") { // rang 233 -> E266
		t.Errorf("ligne sélectionnée absente du rendu:\n%s", b.String())
	}
	if got := fmtInt(23456); got != "23 456" {
		t.Errorf("fmtInt: %q", got)
	}
	if got := fmtInt(999); got != "999" {
		t.Errorf("fmtInt: %q", got)
	}
}
