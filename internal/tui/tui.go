// Package tui implémente l'interface texte sans dépendance externe : mode
// terminal brut via stty, lecture des touches sur stdin, rendu par séquences
// ANSI. Barre de recherche en haut, liste des résultats, détail dessous.
//
// Ce choix « stdlib seule » évite les dépendances réseau non joignables dans
// certains environnements ; il reste facile à remplacer par une lib TUI plus
// riche (bubbletea…) si le réseau le permet.
package tui

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"vulnkb/internal/model"
	"vulnkb/internal/store"
)

// séquences ANSI
const (
	clear    = "\x1b[2J\x1b[H"
	reset    = "\x1b[0m"
	bold     = "\x1b[1m"
	dim      = "\x1b[2m"
	reverse  = "\x1b[7m"
	cyan     = "\x1b[36m"
	hideCur  = "\x1b[?25l"
	showCur  = "\x1b[?25h"
)

type ui struct {
	st       *store.Store
	query    []rune
	results  []model.Advisory
	cursor   int
	rows     int
	cols     int
	total    int
	detFocus bool
	detScr   int
}

// Run lance la boucle interactive et rend la main à la sortie (esc/ctrl+c).
func Run(st *store.Store) error {
	restore, err := rawMode()
	if err != nil {
		return fmt.Errorf("mode terminal brut: %w", err)
	}
	defer restore()

	u := &ui{st: st}
	u.total, _ = st.Count()
	u.rows, u.cols = termSize()
	u.reload()

	fmt.Print(hideCur)
	defer fmt.Print(showCur + reset)

	buf := make([]byte, 8)
	for {
		u.render()
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			return nil
		}
		if u.handle(buf[:n]) { // true => quitter
			return nil
		}
	}
}

func (u *ui) reload() {
	res, err := u.st.Search(string(u.query), 200)
	if err == nil {
		u.results = res
	}
	if u.cursor >= len(u.results) {
		u.cursor = maxi(0, len(u.results)-1)
	}
	u.detScr = 0
}

// handle traite une saisie clavier et renvoie true s'il faut quitter.
func (u *ui) handle(b []byte) bool {
	// touches spéciales
	switch {
	case len(b) == 1 && (b[0] == 3 || b[0] == 27 && false): // ctrl+c
		return true
	case len(b) == 1 && b[0] == 27: // esc seul
		return true
	case b[0] == 27 && len(b) >= 3 && b[1] == '[': // séquence flèche
		switch b[2] {
		case 'A': // haut
			u.moveUp()
		case 'B': // bas
			u.moveDown()
		}
		return false
	case len(b) == 1 && b[0] == '\t': // tab : bascule liste/détail
		u.detFocus = !u.detFocus
		return false
	case len(b) == 1 && (b[0] == 127 || b[0] == 8): // backspace
		if len(u.query) > 0 {
			u.query = u.query[:len(u.query)-1]
			u.reload()
		}
		return false
	}

	// caractères imprimables -> recherche
	changed := false
	for _, r := range string(b) {
		if r >= 0x20 && r != 0x7f {
			u.query = append(u.query, r)
			changed = true
		}
	}
	if changed {
		u.reload()
	}
	return false
}

func (u *ui) moveUp() {
	if u.detFocus {
		u.detScr = maxi(0, u.detScr-1)
	} else if u.cursor > 0 {
		u.cursor--
		u.detScr = 0
	}
}

func (u *ui) moveDown() {
	if u.detFocus {
		u.detScr++
	} else if u.cursor < len(u.results)-1 {
		u.cursor++
		u.detScr = 0
	}
}

func (u *ui) render() {
	u.rows, u.cols = termSize()
	var b strings.Builder
	b.WriteString(clear)

	// en-tête + recherche
	b.WriteString(bold + cyan + " vulnkb " + reset)
	b.WriteString(dim + fmt.Sprintf(" %d entrées · %d résultats", u.total, len(u.results)) + reset + "\r\n")
	focusMark := ""
	if !u.detFocus {
		focusMark = cyan + "▌" + reset
	}
	b.WriteString(focusMark + "recherche: " + bold + string(u.query) + reset + "_\r\n")
	b.WriteString(strings.Repeat("─", maxi(1, u.cols)) + "\r\n")

	// zones : liste (moitié haute) / détail (moitié basse)
	bodyRows := maxi(4, u.rows-5)
	listRows := bodyRows / 2
	detRows := bodyRows - listRows

	u.renderList(&b, listRows)
	b.WriteString(dim + strings.Repeat("┈", maxi(1, u.cols)) + reset + "\r\n")
	u.renderDetail(&b, detRows)

	b.WriteString(dim + "↑/↓ naviguer · tab liste/détail · taper pour filtrer · esc quitter" + reset)
	fmt.Print(b.String())
}

func (u *ui) renderList(b *strings.Builder, h int) {
	if len(u.results) == 0 {
		b.WriteString(dim + "  aucun résultat\r\n" + reset)
		for i := 1; i < h; i++ {
			b.WriteString("\r\n")
		}
		return
	}
	start := 0
	if u.cursor >= h {
		start = u.cursor - h + 1
	}
	printed := 0
	for i := start; i < len(u.results) && printed < h; i++ {
		a := u.results[i]
		id := a.ExternalID
		if id == "" {
			id = a.Source
		}
		line := fmt.Sprintf(" %-16s %s", trunc(id, 16), a.Title)
		line = trunc(line, u.cols)
		if i == u.cursor {
			b.WriteString(reverse + fmt.Sprintf("%-*s", u.cols, line) + reset + "\r\n")
		} else {
			b.WriteString(line + "\r\n")
		}
		printed++
	}
	for printed < h {
		b.WriteString("\r\n")
		printed++
	}
}

func (u *ui) renderDetail(b *strings.Builder, h int) {
	if len(u.results) == 0 || u.cursor >= len(u.results) {
		for i := 0; i < h; i++ {
			b.WriteString("\r\n")
		}
		return
	}
	a := u.results[u.cursor]
	var lines []string
	add := func(label, val string) {
		if strings.TrimSpace(val) == "" {
			return
		}
		lines = append(lines, wrapLines(cyan+label+": "+reset+val, u.cols)...)
	}
	lines = append(lines, wrapLines(bold+a.Title+reset, u.cols)...)
	lines = append(lines, "")
	add("ID", a.ExternalID)
	add("Source", a.Source)
	add("Composant", a.Component)
	add("Type", a.VulnType)
	add("Sévérité", a.Severity)
	add("Versions affectées", a.AffectedVersions)
	add("Corrigé dans", a.FixedVersions)
	if !a.Published.IsZero() {
		add("Publié", a.Published.Format("2006-01-02"))
	}
	if a.Summary != "" {
		lines = append(lines, "")
		lines = append(lines, wrapLines(a.Summary, u.cols)...)
	}
	if strings.TrimSpace(a.Remediation) != "" {
		lines = append(lines, "", cyan+"Remédiation:"+reset)
		lines = append(lines, wrapLines(a.Remediation, u.cols)...)
	}
	if len(a.References) > 0 {
		lines = append(lines, "", cyan+"Références:"+reset)
		for _, r := range a.References {
			lines = append(lines, dim+"  • "+r+reset)
		}
	}

	if u.detScr > maxi(0, len(lines)-1) {
		u.detScr = maxi(0, len(lines)-1)
	}
	view := lines[minInt(u.detScr, len(lines)):]
	printed := 0
	for _, l := range view {
		if printed >= h {
			break
		}
		b.WriteString(l + "\r\n")
		printed++
	}
	for printed < h {
		b.WriteString("\r\n")
		printed++
	}
}

// ---- terminal brut via stty (pas de dépendance golang.org/x/sys) ----

func rawMode() (func(), error) {
	saved, err := stty("-g")
	if err != nil {
		return nil, err
	}
	if _, err := stty("raw", "-echo"); err != nil {
		return nil, err
	}
	return func() {
		stty(strings.Fields(strings.TrimSpace(string(saved)))...)
		fmt.Print(showCur + reset)
	}, nil
}

func stty(args ...string) ([]byte, error) {
	c := exec.Command("stty", args...)
	c.Stdin = os.Stdin
	return c.Output()
}

func termSize() (rows, cols int) {
	rows, cols = 24, 80
	out, err := stty("size")
	if err != nil {
		return
	}
	parts := bytes.Fields(out)
	if len(parts) == 2 {
		if r, err := strconv.Atoi(string(parts[0])); err == nil {
			rows = r
		}
		if c, err := strconv.Atoi(string(parts[1])); err == nil {
			cols = c
		}
	}
	return
}

// ---- utilitaires texte (tiennent compte des séquences ANSI) ----

// trunc coupe une chaîne à n colonnes visibles, en ignorant les codes ANSI.
func trunc(s string, n int) string {
	if n <= 0 {
		return ""
	}
	var out strings.Builder
	visible := 0
	inEsc := false
	for _, r := range s {
		if r == 0x1b {
			inEsc = true
		}
		if inEsc {
			out.WriteRune(r)
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		if visible >= n {
			break
		}
		out.WriteRune(r)
		visible++
	}
	return out.String()
}

// wrapLines découpe un texte en lignes d'au plus w colonnes visibles.
func wrapLines(s string, w int) []string {
	if w <= 0 {
		return []string{s}
	}
	var lines []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			lines = append(lines, "")
			continue
		}
		cur := ""
		curLen := 0
		for _, word := range words {
			wl := visibleLen(word)
			if curLen > 0 && curLen+1+wl > w {
				lines = append(lines, cur)
				cur, curLen = "", 0
			}
			if curLen > 0 {
				cur += " "
				curLen++
			}
			cur += word
			curLen += wl
		}
		if cur != "" {
			lines = append(lines, cur)
		}
	}
	return lines
}

func visibleLen(s string) int {
	n := 0
	inEsc := false
	for _, r := range s {
		if r == 0x1b {
			inEsc = true
		}
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		n++
	}
	return n
}

func maxi(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
