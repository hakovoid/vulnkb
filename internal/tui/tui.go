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
	clear   = "\x1b[2J\x1b[H"
	reset   = "\x1b[0m"
	bold    = "\x1b[1m"
	dim     = "\x1b[2m"
	reverse = "\x1b[7m"
	cyan    = "\x1b[36m"
	hideCur = "\x1b[?25l"
	showCur = "\x1b[?25h"
)

const titleColor = "\x1b[1;93m"

// window est le nombre de résultats gardés en mémoire autour de la position
// courante ; le reste est relu en base à la demande.
const window = 200

type ui struct {
	st       *store.Store
	query    []rune
	results  []model.Advisory // résultats de rang offset à offset+len-1
	offset   int
	matches  int // nombre total de résultats de la recherche
	cursor   int // rang absolu de l'entrée sélectionnée
	top      int // rang de la première ligne affichée
	listH    int
	detH     int
	rows     int
	cols     int
	total    int
	detFocus bool
	detScr   int
	help     bool
	helpScr  int
	gotoMode bool
	gotoBuf  []rune
	kev      map[string][]store.Ref // CVE -> entrées CISA KEV
	certfr   map[string][]store.Ref // CVE -> avis CERT-FR
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
	u.kev, _ = st.CVEIndex("cisa-kev")
	u.certfr, _ = st.CVEIndex("certfr")
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

// reload relance la recherche après un changement de saisie.
func (u *ui) reload() {
	if n, err := u.st.CountMatches(string(u.query)); err == nil {
		u.matches = n
	} else {
		u.matches = 0
	}
	u.cursor, u.top, u.offset, u.detScr = 0, 0, 0, 0
	u.results = nil
	u.fetchWindow(0)
}

func (u *ui) fetchWindow(offset int) {
	res, err := u.st.SearchPage(string(u.query), offset, window)
	if err != nil {
		res = nil
	}
	u.offset, u.results = offset, res
}

// current renvoie l'entrée sélectionnée.
func (u *ui) current() (model.Advisory, bool) {
	i := u.cursor - u.offset
	if i < 0 || i >= len(u.results) {
		return model.Advisory{}, false
	}
	return u.results[i], true
}

// setCursor place la sélection au rang n (borné aux résultats).
func (u *ui) setCursor(n int) {
	n = maxi(0, minInt(n, u.matches-1))
	if n != u.cursor {
		u.cursor, u.detScr = n, 0
	}
	u.ensureVisible(maxi(1, u.listH))
}

// ensureVisible fait défiler la liste pour montrer la sélection, et recharge
// la fenêtre en mémoire si les lignes à afficher en sortent.
func (u *ui) ensureVisible(h int) {
	if u.cursor < u.top {
		u.top = u.cursor
	}
	if u.cursor >= u.top+h {
		u.top = u.cursor - h + 1
	}
	u.top = maxi(0, minInt(u.top, u.matches-h))
	end := minInt(u.top+h, u.matches)
	if u.top < u.offset || end > u.offset+len(u.results) {
		u.fetchWindow(maxi(0, u.top-(window-h)/2))
	}
}

// keys associe les séquences envoyées par le terminal aux touches spéciales.
var keys = map[string]string{
	"\x1b[A": "up", "\x1bOA": "up",
	"\x1b[B": "down", "\x1bOB": "down",
	"\x1b[5~": "pgup", "\x1b[6~": "pgdn",
	"\x1b[H": "home", "\x1bOH": "home", "\x1b[1~": "home", "\x1b[7~": "home",
	"\x1b[F": "end", "\x1bOF": "end", "\x1b[4~": "end", "\x1b[8~": "end",
}

// handle traite une saisie clavier et renvoie true s'il faut quitter.
func (u *ui) handle(b []byte) bool {
	if len(b) == 1 && b[0] == 3 { // ctrl+c
		return true
	}
	key := keys[string(b)]
	if u.help {
		switch {
		case len(b) == 1 && (b[0] == 27 || b[0] == '?' || b[0] == 'q'):
			u.help = false
		case key == "up":
			u.helpScr = maxi(0, u.helpScr-1)
		case key == "down":
			u.helpScr++
		case key == "pgup":
			u.helpScr = maxi(0, u.helpScr-u.listH)
		case key == "pgdn":
			u.helpScr += u.listH
		}
		return false
	}
	if u.gotoMode {
		u.handleGoto(b)
		return false
	}

	switch key {
	case "up":
		u.moveUp()
		return false
	case "down":
		u.moveDown()
		return false
	case "pgup", "pgdn", "home", "end":
		u.jump(key)
		return false
	}

	// touches spéciales
	switch {
	case len(b) == 1 && b[0] == '?':
		u.help, u.helpScr = true, 0
		return false
	case len(b) == 1 && b[0] == 7: // ctrl+g : aller à une entrée
		u.gotoMode, u.gotoBuf = true, nil
		return false
	case len(b) == 1 && b[0] == 27: // esc seul
		return true
	case b[0] == 27: // autre séquence non gérée
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
	} else {
		u.setCursor(u.cursor - 1)
	}
}

func (u *ui) moveDown() {
	if u.detFocus {
		u.detScr++
	} else {
		u.setCursor(u.cursor + 1)
	}
}

// jump gère PgUp/PgDn/Début/Fin, dans la liste ou dans le détail.
func (u *ui) jump(key string) {
	if u.detFocus {
		switch key {
		case "pgup":
			u.detScr = maxi(0, u.detScr-maxi(1, u.detH-1))
		case "pgdn":
			u.detScr += maxi(1, u.detH-1)
		case "home":
			u.detScr = 0
		case "end":
			u.detScr = 1 << 30 // borné au rendu
		}
		return
	}
	page := maxi(1, u.listH-1)
	switch key {
	case "pgup":
		u.setCursor(u.cursor - page)
	case "pgdn":
		u.setCursor(u.cursor + page)
	case "home":
		u.setCursor(0)
	case "end":
		u.setCursor(u.matches - 1)
	}
}

// handleGoto gère la saisie du numéro d'entrée après Ctrl-G.
func (u *ui) handleGoto(b []byte) {
	switch {
	case len(b) == 1 && b[0] == 27:
		u.gotoMode = false
	case len(b) == 1 && (b[0] == '\r' || b[0] == '\n'):
		u.gotoMode = false
		if n, err := strconv.Atoi(string(u.gotoBuf)); err == nil && n >= 1 {
			u.detFocus = false
			u.top = n - 1 - u.listH/2 // centre l'entrée à l'écran
			u.setCursor(n - 1)
		}
	case len(b) == 1 && (b[0] == 127 || b[0] == 8):
		if len(u.gotoBuf) > 0 {
			u.gotoBuf = u.gotoBuf[:len(u.gotoBuf)-1]
		}
	default:
		for _, r := range string(b) {
			if r >= '0' && r <= '9' && len(u.gotoBuf) < 9 {
				u.gotoBuf = append(u.gotoBuf, r)
			}
		}
	}
}

// fmtInt groupe les milliers : 23456 -> « 23 456 ».
func fmtInt(n int) string {
	s := strconv.Itoa(n)
	var out []byte
	for i := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ' ')
		}
		out = append(out, s[i])
	}
	return string(out)
}

func (u *ui) render() {
	u.rows, u.cols = termSize()
	var b strings.Builder
	b.WriteString(clear)

	// en-tête + recherche
	b.WriteString(bold + cyan + " vulnkb " + reset)
	pos := "aucun résultat"
	if u.matches > 0 {
		pos = bold + "résultat " + fmtInt(u.cursor+1) + reset + dim + " / " + fmtInt(u.matches)
	}
	b.WriteString(trunc(dim+" "+fmtInt(u.total)+" entrées · "+reset+dim+pos+reset, u.cols-8) + reset + "\r\n")
	if u.gotoMode {
		b.WriteString(trunc(titleColor+"aller à l'entrée n° : "+reset+bold+string(u.gotoBuf)+reset+"_"+
			dim+"  (1 à "+fmtInt(u.matches)+" · Entrée valider · Esc annuler)"+reset, u.cols) + "\r\n")
	} else {
		focusMark := ""
		if !u.detFocus {
			focusMark = cyan + "▌" + reset
		}
		b.WriteString(trunc(focusMark+"recherche: "+bold+string(u.query)+reset+"_"+describeFilters(store.ParseQuery(string(u.query))), u.cols) + reset + "\r\n")
	}
	b.WriteString(strings.Repeat("─", maxi(1, u.cols)) + "\r\n")

	bodyRows := maxi(4, u.rows-4)
	if u.help {
		u.listH = bodyRows
		u.renderHelp(&b, bodyRows)
		b.WriteString(dim + trunc("↑/↓ PgUp/PgDn défiler · ? ou esc fermer l'aide", u.cols) + reset)
		fmt.Print(b.String())
		return
	}

	// zones : liste (moitié haute) / détail (moitié basse)
	u.listH = (bodyRows - 1) / 2
	u.detH = bodyRows - 1 - u.listH

	u.renderList(&b, u.listH)
	b.WriteString(dim + strings.Repeat("┈", maxi(1, u.cols)) + reset + "\r\n")
	u.renderDetail(&b, u.detH)

	b.WriteString(dim + trunc("↑↓ PgUp PgDn Début Fin naviguer · ^G aller au n° · tab détail · ? aide · esc quitter", u.cols) + reset)
	fmt.Print(b.String())
}

func (u *ui) renderHelp(b *strings.Builder, h int) {
	var lines []string
	for _, l := range helpText {
		if visibleLen(l) <= u.cols {
			lines = append(lines, l) // garde l'alignement des colonnes
		} else {
			lines = append(lines, wrapLines(l, u.cols)...)
		}
	}
	u.helpScr = minInt(u.helpScr, maxi(0, len(lines)-h))
	printed := 0
	for _, l := range lines[u.helpScr:] {
		if printed >= h {
			break
		}
		b.WriteString(l + "\r\n")
		printed++
	}
	for ; printed < h; printed++ {
		b.WriteString("\r\n")
	}
}

// exploited indique si l'entrée, ou l'un de ses CVE, figure au catalogue KEV.
func (u *ui) exploited(a model.Advisory) bool {
	if a.Source == "cisa-kev" {
		return true
	}
	for _, c := range store.CVEs(a.ExternalID) {
		if len(u.kev[c]) > 0 {
			return true
		}
	}
	return false
}

// certfrRefs renvoie les avis CERT-FR qui citent un CVE de l'entrée.
func (u *ui) certfrRefs(a model.Advisory) []store.Ref {
	if a.Source == "certfr" {
		return nil
	}
	seen := map[string]bool{}
	var out []store.Ref
	for _, c := range store.CVEs(a.ExternalID) {
		for _, r := range u.certfr[c] {
			if !seen[r.ID] {
				seen[r.ID] = true
				out = append(out, r)
			}
		}
	}
	return out
}

func (u *ui) renderList(b *strings.Builder, h int) {
	if u.matches == 0 {
		b.WriteString(dim + "  aucun résultat\r\n" + reset)
		for i := 1; i < h; i++ {
			b.WriteString("\r\n")
		}
		return
	}
	u.ensureVisible(h)
	printed := 0
	for i := u.top; i < u.matches && printed < h; i++ {
		j := i - u.offset
		if j < 0 || j >= len(u.results) {
			break
		}
		a := u.results[j]
		id := primaryID(a.ExternalID)
		if id == "" {
			id = a.Source
		}
		mark := " "
		if u.exploited(a) {
			mark = "●"
		}
		sev := effectiveSeverity(a)
		src := sourceOf(a.Source)
		title := strings.ReplaceAll(a.Title, "\n", " ")
		idCol := fmt.Sprintf("%-20s", trunc(id, 20))

		if i == u.cursor { // ligne sélectionnée : vidéo inverse, sans couleurs
			line := trunc(fmt.Sprintf(" %s %s %s %s %s", mark, sev.short(), src.badge, idCol, title), u.cols)
			b.WriteString(reverse + line + strings.Repeat(" ", maxi(0, u.cols-visibleLen(line))) + reset + "\r\n")
		} else {
			line := fmt.Sprintf(" %s %s %s %s %s",
				boldRed+mark+reset, sev.color()+sev.short()+reset, src.color+src.badge+reset, idCol, title)
			b.WriteString(trunc(line, u.cols) + reset + "\r\n")
		}
		printed++
	}
	for printed < h {
		b.WriteString("\r\n")
		printed++
	}
}

func (u *ui) renderDetail(b *strings.Builder, h int) {
	a, ok := u.current()
	if !ok {
		for i := 0; i < h; i++ {
			b.WriteString("\r\n")
		}
		return
	}
	var lines []string
	add := func(label, val string) {
		if strings.TrimSpace(val) == "" {
			return
		}
		lines = append(lines, wrapLines(cyan+label+": "+reset+val, u.cols)...)
	}
	lines = append(lines, wrapLines(titleColor+a.Title+reset, u.cols)...)
	lines = append(lines, "")
	add("ID", a.ExternalID)
	src := sourceOf(a.Source)
	add("Source", src.color+src.name+reset)
	if u.exploited(a) {
		add("Exploitation", boldRed+"exploitée activement (catalogue CISA KEV)"+reset)
	}
	if sev := parseSeverity(a.Severity); sev.level > 0 {
		txt := sev.color() + sev.label() + reset
		if sev.score != "" {
			txt += dim + " · CVSS " + sev.score + " (" + a.Severity + ")" + reset
		}
		add("Sévérité", txt)
	} else if a.NVD.CVE != "" {
		nv := severity{level: a.NVD.Level}
		add("Sévérité", nv.color()+nv.label()+reset+dim+" · d'après NVD"+reset)
	} else if a.Source != "cisa-kev" && a.Source != "certfr" {
		add("Sévérité", a.Severity)
	}
	if a.NVD.CVE != "" {
		add("CVSS (NVD)", describeNVD(a.NVD, len(store.CVEs(a.ExternalID))))
	}
	add("Composant", a.Component)
	if a.VulnType == "" && a.NVD.CWE != "" {
		add("Type", describeCWEs(a.NVD.CWE)+dim+" (NVD)"+reset)
	} else {
		add("Type", describeCWEs(a.VulnType))
	}
	add("Versions affectées", a.AffectedVersions)
	add("Corrigé dans", a.FixedVersions)
	add("Remédiation", a.Remediation)
	if !a.Published.IsZero() {
		add("Publié", a.Published.Format("2006-01-02"))
	}
	for _, r := range u.certfrRefs(a) {
		add("Avis CERT-FR", blue+r.ID+reset+" "+r.Title+dim+" "+r.URL+reset)
	}
	if a.Summary != "" {
		lines = append(lines, "")
		lines = append(lines, wrapLines(cleanMarkdown(a.Summary), u.cols)...)
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
