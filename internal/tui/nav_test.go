package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"vulnkb/internal/model"
	"vulnkb/internal/store"
)

// navUI prépare une interface de 120×40 sur n entrées publiées un jour
// d'écart : le rang k (0 = plus récente) correspond à l'entrée « E<n-1-k> ».
func navUI(t *testing.T, n int) *ui {
	t.Helper()
	s, err := store.Open(t.TempDir() + "/nav.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	var advs []model.Advisory
	for i := 0; i < n; i++ {
		title := "entrée banale"
		if i%10 == 0 {
			title = "entrée spéciale"
		}
		advs = append(advs, model.Advisory{
			ID: fmt.Sprintf("t:%d", i), Source: "osv", ExternalID: fmt.Sprintf("E%d", i),
			Title: title, Severity: "HIGH", FixedVersions: "lib 1.2.3", Published: base.AddDate(0, 0, i),
		})
	}
	if _, err := s.Upsert(advs); err != nil {
		t.Fatal(err)
	}
	m := newUI(s)
	m.syncSearch = true
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	return m
}

var specialKeys = map[string]tea.KeyType{
	"up": tea.KeyUp, "down": tea.KeyDown, "pgup": tea.KeyPgUp, "pgdown": tea.KeyPgDown,
	"home": tea.KeyHome, "end": tea.KeyEnd, "enter": tea.KeyEnter, "esc": tea.KeyEsc,
	"tab": tea.KeyTab, "ctrl+g": tea.KeyCtrlG, "backspace": tea.KeyBackspace,
}

// press envoie des touches ; un nom de touche spéciale, sinon du texte tapé.
func press(m *ui, keys ...string) (cmds []tea.Cmd) {
	for _, k := range keys {
		msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		if t, ok := specialKeys[k]; ok {
			msg = tea.KeyMsg{Type: t}
		}
		_, cmd := m.Update(msg)
		cmds = append(cmds, cmd)
	}
	return cmds
}

func selected(t *testing.T, m *ui) string {
	t.Helper()
	a, ok := m.current()
	if !ok {
		t.Fatalf("aucune entrée sélectionnée (curseur %d, fenêtre %d+%d)", m.cursor, m.offset, len(m.results))
	}
	return a.ExternalID
}

func TestGotoAndJumps(t *testing.T) {
	m := navUI(t, 500)
	if m.matches != 500 || len(m.results) != window || m.listH < 10 {
		t.Fatalf("chargement initial: %d résultats, %d en mémoire, %d lignes", m.matches, len(m.results), m.listH)
	}

	press(m, "ctrl+g", "4", "5", "x", "6", "enter") // le x est ignoré
	if m.cursor != 455 || selected(t, m) != "E44" || m.gotoMode {
		t.Errorf("Ctrl-G 456: curseur %d, entrée %s", m.cursor, selected(t, m))
	}
	if m.top > m.cursor || m.cursor >= m.top+m.listH {
		t.Errorf("sélection hors écran: top %d, curseur %d", m.top, m.cursor)
	}

	press(m, "end")
	if m.cursor != 499 || selected(t, m) != "E0" {
		t.Errorf("Fin: curseur %d", m.cursor)
	}
	press(m, "home", "pgdown")
	if m.cursor != m.listH-1 || selected(t, m) != fmt.Sprintf("E%d", 499-(m.listH-1)) {
		t.Errorf("PgDn: curseur %d", m.cursor)
	}
	press(m, "ctrl+g", "99999", "enter") // au-delà du dernier : borné
	if m.cursor != 499 {
		t.Errorf("Ctrl-G trop grand: curseur %d", m.cursor)
	}
	press(m, "ctrl+g", "1", "esc") // Esc annule
	if m.cursor != 499 || m.gotoMode {
		t.Errorf("Esc n'annule pas: curseur %d", m.cursor)
	}
}

func TestSearchResetsPosition(t *testing.T) {
	m := navUI(t, 500)
	press(m, "end", "spéciale")
	if m.matches != 50 || m.cursor != 0 || m.input.Value() != "spéciale" {
		t.Fatalf("recherche: %d résultats, curseur %d, saisie %q", m.matches, m.cursor, m.input.Value())
	}
	press(m, "end")
	if m.cursor != 49 {
		t.Errorf("Fin sur recherche: curseur %d", m.cursor)
	}
	press(m, "backspace")
	if m.input.Value() != "spécial" || m.cursor != 0 {
		t.Errorf("retour arrière: %q, curseur %d", m.input.Value(), m.cursor)
	}
}

func TestStaleSearchIgnored(t *testing.T) {
	m := navUI(t, 50)
	m.syncSearch = false
	press(m, "s")
	old := runSearch(m.st, m.seq-1, "ancienne")
	m.Update(old)
	if m.query == "ancienne" {
		t.Error("réponse d'une recherche périmée appliquée")
	}
	m.Update(runSearch(m.st, m.seq, "spéciale"))
	if m.query != "spéciale" || m.matches != 5 {
		t.Errorf("réponse courante non appliquée: %q, %d", m.query, m.matches)
	}
}

func TestModesAndQuit(t *testing.T) {
	m := navUI(t, 50)
	press(m, "enter")
	if !m.zoom {
		t.Fatal("Entrée n'ouvre pas la fiche")
	}
	if cmds := press(m, "esc"); m.zoom || cmds[0] != nil {
		t.Error("Esc en plein écran doit revenir à la liste, pas quitter")
	}
	press(m, "?")
	if !m.help {
		t.Fatal("? n'ouvre pas l'aide")
	}
	press(m, "esc")
	if m.help {
		t.Error("Esc ne ferme pas l'aide")
	}
	cmds := press(m, "esc")
	if cmds[0] == nil {
		t.Fatal("Esc ne quitte pas")
	}
	if _, ok := cmds[0]().(tea.QuitMsg); !ok {
		t.Error("Esc ne renvoie pas tea.Quit")
	}
}

func TestViewRendersLayout(t *testing.T) {
	m := navUI(t, 500)
	press(m, "ctrl+g", "234", "enter")
	v := m.View()
	for _, want := range []string{"vulnkb", "résultat 234", "/ 500", "RÉSULTATS", "DÉTAIL", "E266", "ÉLEVÉ",
		"Corrigé dans", "lib 1.2.3", "fiche"} {
		if !strings.Contains(stripANSI(v), want) {
			t.Errorf("rendu sans %q", want)
		}
	}
	lines := strings.Split(v, "\n")
	if len(lines) != 40 {
		t.Errorf("rendu de %d lignes pour un terminal de 40", len(lines))
	}
	for i, l := range lines {
		if w := visibleLen(l); w > 120 {
			t.Errorf("ligne %d trop large (%d colonnes): %q", i, w, stripANSI(l))
		}
	}

	m.Update(tea.WindowSizeMsg{Width: 80, Height: 30}) // terminal étroit : panneaux empilés
	if v := m.View(); len(strings.Split(v, "\n")) != 30 || !strings.Contains(stripANSI(v), "DÉTAIL") {
		t.Errorf("rendu étroit incorrect:\n%s", stripANSI(v))
	}
	if got := fmtInt(23456); got != "23 456" {
		t.Errorf("fmtInt: %q", got)
	}
	if got := syncAge(time.Now().Add(-2*time.Hour-time.Minute), time.Now()); got != "il y a 2 h" {
		t.Errorf("syncAge: %q", got)
	}
}

func TestSplitResize(t *testing.T) {
	m := navUI(t, 50) // 120 de large → disposition côte à côte
	def := m.geometry().listW
	press(m, "ctrl+right")
	if m.geometry().listW <= def {
		t.Errorf("Ctrl-→ n'élargit pas la liste (%d ≤ %d)", m.geometry().listW, def)
	}
	press(m, "ctrl+left", "ctrl+left")
	if m.geometry().listW >= def {
		t.Errorf("Ctrl-← ne rétrécit pas la liste")
	}
	// bornes respectées
	for i := 0; i < 40; i++ {
		press(m, "ctrl+left")
	}
	if m.splitPct != splitMin {
		t.Errorf("borne basse non respectée: %d", m.splitPct)
	}
	for i := 0; i < 40; i++ {
		press(m, "ctrl+right")
	}
	if m.splitPct != splitMax {
		t.Errorf("borne haute non respectée: %d", m.splitPct)
	}
	// glissé souris à ~30 % de la largeur
	m.Update(tea.MouseMsg{X: 36, Y: 10, Action: tea.MouseActionMotion, Button: tea.MouseButtonLeft})
	if m.splitPct != 30 {
		t.Errorf("glissé souris: splitPct=%d, attendu 30", m.splitPct)
	}
	// molette dans la liste fait descendre le curseur
	before := m.cursor
	m.Update(tea.MouseMsg{X: 5, Y: 8, Button: tea.MouseButtonWheelDown})
	if m.cursor <= before {
		t.Errorf("molette liste: curseur %d → %d", before, m.cursor)
	}
}
