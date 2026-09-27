package tui

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"vulnkb/internal/model"
	"vulnkb/internal/store"
)

// Hauteurs fixes : en-tête, barre de recherche (bordure comprise), statut.
const (
	headerH = 1
	searchH = 3
	statusH = 1
	labelW  = 19 // colonne des libellés de la fiche
)

// geometry décrit la place de chaque panneau, recalculée à chaque changement
// de taille ou de mode.
type geometry struct {
	stacked      bool // terminal étroit : liste au-dessus du détail
	listW, listH int  // taille extérieure du panneau liste (0 = masqué)
	detW, detH   int
}

// layout recalcule la taille des panneaux et de la fiche.
func (m *ui) layout() {
	g := m.geometry()
	m.listH = max(1, g.listH-2-2-1) // bordures, titre + séparateur, pied
	m.detail.Width = max(10, g.detW-4)
	m.detail.Height = max(1, g.detH-2-2-1)
	m.detailID = "" // largeur changée : fiche à recomposer
	if m.listH > 0 {
		m.ensureVisible()
	}
	m.syncDetail()
}

func (m *ui) geometry() geometry {
	body := max(6, m.height-headerH-searchH-statusH)
	w := max(40, m.width)
	switch {
	case m.zoom:
		return geometry{detW: w, detH: body}
	case w >= 100:
		pct := m.splitPct
		if pct == 0 {
			pct = splitDefault
		}
		lw := max(30, min(w-30, w*pct/100))
		return geometry{listW: lw, listH: body, detW: w - lw - 1, detH: body}
	default:
		lh := max(7, body*45/100)
		return geometry{stacked: true, listW: w, listH: lh, detW: w, detH: body - lh}
	}
}

// syncDetail recompose la fiche quand la sélection ou la largeur change.
func (m *ui) syncDetail() {
	a, ok := m.current()
	key := ""
	if ok {
		key = a.ID
	}
	key += fmt.Sprintf("|%d", m.detail.Width)
	if key == m.detailID {
		return
	}
	m.detailID = key
	if !ok {
		m.detail.SetContent(sty.muted.Render("Aucune entrée sélectionnée."))
	} else {
		m.detail.SetContent(strings.Join(m.detailLines(a, m.detail.Width), "\n"))
	}
	m.detail.GotoTop()
}

func (m *ui) View() string {
	if m.width == 0 {
		return "chargement…"
	}
	w := max(40, m.width)
	var parts []string
	parts = append(parts, m.headerView(w), m.searchView(w))

	g := m.geometry()
	switch {
	case m.srcView:
		parts = append(parts, m.overlayView(w, max(6, m.height-headerH-searchH-statusH), "SOURCES", m.srcLines,
			"┄ ↑↓ défiler · alt+s ou esc pour fermer"))
	case m.help:
		parts = append(parts, m.helpView(w, max(6, m.height-headerH-searchH-statusH)))
	case g.listW == 0:
		parts = append(parts, m.detailPanel(g.detW, g.detH))
	case g.stacked:
		parts = append(parts, m.listPanel(g.listW, g.listH), m.detailPanel(g.detW, g.detH))
	default:
		parts = append(parts, lipgloss.JoinHorizontal(lipgloss.Top,
			m.listPanel(g.listW, g.listH), " ", m.detailPanel(g.detW, g.detH)))
	}
	parts = append(parts, m.statusView(w))
	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

// ---- en-tête, recherche, statut ----

func (m *ui) headerView(w int) string {
	badge := lipgloss.NewStyle().Bold(true).Padding(0, 1).
		Foreground(lipgloss.Color(pal.onAccent)).Background(lipgloss.Color(pal.accent)).Render("vulnkb")
	pos := "aucun résultat"
	if m.matches > 0 {
		pos = sty.text.Render("résultat "+fmtInt(m.cursor+1)) + sty.muted.Render(" / "+fmtInt(m.matches))
	}
	left := badge + "  " + sty.muted.Render(fmtInt(m.total)+" entrées") + sty.faint.Render("  ·  ") + pos

	dot, age := pal.green, time.Since(m.lastSync)
	switch {
	case m.lastSync.IsZero() || age > 7*24*time.Hour:
		dot = pal.red
	case age > 36*time.Hour:
		dot = pal.yellow
	}
	right := sty.muted.Render(humanBytes(m.dbSize)) + sty.faint.Render("  ·  ") +
		lipgloss.NewStyle().Foreground(lipgloss.Color(dot)).Render("●") + " " +
		sty.muted.Render("sync "+syncAge(m.lastSync, time.Now()))

	gap := w - visibleLen(left) - visibleLen(right)
	if gap < 2 {
		return truncEllipsis(left, w)
	}
	return left + strings.Repeat(" ", gap) + right
}

func (m *ui) searchView(w int) string {
	box := sty.search
	if m.detFocus || m.zoom || m.help || m.srcView {
		box = sty.searchIdle
	}
	inner := w - 4
	prefix := sty.accent.Render("❯ ")
	var content string
	if m.gotoMode {
		content = prefix + sty.muted.Render("aller au n°") + sty.faint.Render(" │ ") +
			sty.bright.Render(m.gotoBuf) + sty.accent.Render("▌") +
			sty.muted.Render(fmt.Sprintf("   1 à %s · entrée valider · esc annuler", fmtInt(m.matches)))
	} else {
		label := prefix + sty.muted.Render("recherche") + sty.faint.Render(" │ ")
		filters := describeFilters(store.ParseQuery(m.input.Value()))
		m.input.Width = max(10, inner-visibleLen(label)-visibleLen(filters)-1)
		content = label + m.input.View() + filters
	}
	return box.Width(w - 2).Render(truncEllipsis(content, inner))
}

func (m *ui) statusView(w int) string {
	type kv struct{ k, v string }
	var items []kv
	switch {
	case m.srcView:
		items = []kv{{"↑↓", "défiler"}, {"alt+s esc", "fermer"}}
	case m.help:
		items = []kv{{"↑↓", "défiler"}, {"? esc", "fermer l'aide"}}
	case m.gotoMode:
		items = []kv{{"0-9", "numéro"}, {"entrée", "aller"}, {"esc", "annuler"}}
	case m.zoom:
		items = []kv{{"↑↓ pgup pgdn", "défiler"}, {"entrée esc", "revenir à la liste"}, {"? ", "aide"}}
	default:
		items = []kv{{"↑↓", "naviguer"}, {"tab", "détail"}, {"entrée", "fiche"}, {"alt+t", "mes"},
			{"alt+o", "tri"}, {"alt+g", "n°"}, {"alt+s", "sources"}, {"alt+y", "thème"}, {"?", "aide"}, {"esc", "quitter"}}
	}
	var parts []string
	if m.flash != "" {
		parts = append(parts, sty.accent.Render("● "+m.flash))
	}
	for _, it := range items {
		parts = append(parts, sty.key.Render(strings.TrimSpace(it.k))+" "+sty.muted.Render(it.v))
	}
	return " " + truncEllipsis(strings.Join(parts, "   "), w-1)
}

// ---- panneaux ----

// panel encadre un contenu : titre, séparateur, lignes, pied.
func panel(w, h int, focused bool, title, titleRight string, body []string, footer string) string {
	innerW, innerH := max(1, w-4), max(3, h-2)
	style := sty.panel
	if focused {
		style = sty.panelFocus
	}
	head := sty.muted.Render(title)
	if titleRight != "" {
		if gap := innerW - visibleLen(head) - visibleLen(titleRight); gap > 1 {
			head += strings.Repeat(" ", gap) + titleRight
		}
	}
	lines := []string{truncEllipsis(head, innerW), sty.faint.Render(strings.Repeat("─", innerW))}
	rows := innerH - 3
	for i := 0; i < rows; i++ {
		l := ""
		if i < len(body) {
			l = body[i]
		}
		lines = append(lines, l)
	}
	lines = append(lines, truncEllipsis(footer, innerW))
	for i, l := range lines {
		if pad := innerW - visibleLen(l); pad > 0 {
			lines[i] = l + strings.Repeat(" ", pad)
		} else {
			lines[i] = trunc(l, innerW)
		}
	}
	return style.Width(innerW + 2).Render(strings.Join(lines, "\n"))
}

func (m *ui) listPanel(w, h int) string {
	innerW := max(1, w-4)
	var rows []string
	if m.matches == 0 {
		rows = append(rows, sty.muted.Render("Aucun résultat."))
		if m.query != "" {
			rows = append(rows, "", sty.faint.Render("Essaie un début de mot, ou retire un filtre."))
		}
	}
	for i := m.top; i < m.matches && len(rows) < m.listH; i++ {
		j := i - m.offset
		if j < 0 || j >= len(m.results) {
			break
		}
		rows = append(rows, m.listRow(m.results[j], i == m.cursor, innerW))
	}
	footer := ""
	if rest := m.matches - (m.top + m.listH); rest > 0 {
		footer = sty.faint.Render(fmt.Sprintf("%s autres ↓", fmtInt(rest)))
	}
	right := sty.faint.Render("tri " + store.SortLabel(m.sort))
	if m.matches > 0 {
		right += sty.faint.Render("  ·  " + fmtInt(m.cursor+1) + " / " + fmtInt(m.matches))
	}
	return panel(w, h, !m.detFocus, "RÉSULTATS", right, rows, footer)
}

// listRow compose une ligne : barre de sélection, marqueur « exploitée »,
// identifiant, badge de sévérité, source, titre.
func (m *ui) listRow(a model.Advisory, selected bool, w int) string {
	idW := 20 // GHSA (19) et CERT-FR (20) en entier
	if w < 56 {
		idW = 15
	}
	showSrc := w >= 64
	id := primaryID(a.ExternalID)
	if id == "" {
		id = a.Source
	}

	bg := lipgloss.NewStyle()
	if selected {
		bg = sty.selected
	}
	seg := func(s lipgloss.Style, text string) string { return s.Inherit(bg).Render(text) }

	bar := seg(bg, " ")
	if selected {
		bar = seg(sty.accent, "▌")
	}
	mark := seg(bg, " ")
	if m.exploited(a) {
		mark = seg(lipgloss.NewStyle().Foreground(lipgloss.Color(pal.red)).Bold(true), "●")
	}
	idStyle := sty.id
	if selected {
		idStyle = idStyle.Bold(true)
	}
	idCell := seg(idStyle.Width(idW), truncEllipsis(id, idW))
	badge := sevBadge(effectiveSeverity(a).level)

	line := bar + mark + seg(bg, " ") + idCell + seg(bg, " ") + badge + seg(bg, " ")
	switch {
	case m.sort == store.SortEPSS && w >= 40:
		e := "—"
		if a.EPSS > 0 {
			e = fmtPct(a.EPSS)
		}
		line += seg(lipgloss.NewStyle().Foreground(lipgloss.Color(epssHex(a.EPSS))).Width(7).Align(lipgloss.Right), e) + seg(bg, "  ")
	case showSrc:
		src := sourceOf(a.Source)
		line += seg(sty.faint.Width(4), strings.TrimSpace(src.badge)) + seg(bg, " ")
	}
	titleStyle := sty.text
	if selected {
		titleStyle = sty.bright
	}
	rest := w - visibleLen(line)
	line += seg(titleStyle.Width(max(1, rest)), truncEllipsis(oneLine(a.Title), rest))
	return line
}

func (m *ui) detailPanel(w, h int) string {
	title := "DÉTAIL"
	if m.zoom {
		title = "FICHE"
	}
	right := ""
	if m.detail.TotalLineCount() > m.detail.Height {
		right = sty.faint.Render(fmt.Sprintf("%3.0f %%", m.detail.ScrollPercent()*100))
	}
	hint := "tab · défiler la fiche   entrée · plein écran"
	switch {
	case m.zoom:
		hint = "↑↓ pgup pgdn · défiler   entrée/esc · revenir"
	case m.detFocus:
		hint = "↑↓ pgup pgdn · défiler   tab · revenir à la liste"
	}
	body := strings.Split(m.detail.View(), "\n")
	return panel(w, h, m.detFocus || m.zoom, title, right, body, sty.faint.Render("┄ "+hint))
}

// actionLines est le bloc « Que faire » en tête de fiche : il synthétise la
// priorité (faille exploitée) et l'action concrète (correctif ou remédiation),
// avec le lien le plus utile. Vide si rien d'actionnable n'est connu.
func (m *ui) actionLines(a model.Advisory, w int) []string {
	var body []string
	switch {
	case m.exploited(a):
		body = append(body, boldRed+"⚠ exploitée activement — à corriger en priorité"+reset)
	case len(m.exploitsFor(a)) > 0:
		body = append(body, magenta+"⚑ exploit public disponible — à traiter en priorité"+reset)
	case a.EPSS >= 0.1:
		body = append(body, orange+"⚑ forte probabilité d'exploitation (EPSS "+fmtPct(a.EPSS)+") — à traiter en priorité"+reset)
	}
	switch {
	case a.FixedVersions != "":
		body = append(body, wrapLines(sty.green.Render("↑ mettre à jour : ")+a.FixedVersions, w)...)
	case strings.TrimSpace(shortRemediation(a.Remediation)) != "":
		body = append(body, wrapLines(sty.accent.Render("→ ")+oneLine(shortRemediation(a.Remediation)), w)...)
	default:
		body = append(body, sty.muted.Render("Pas de correctif indiqué — voir les références ci-dessous."))
	}
	if link := fixLink(a.References); link != "" {
		body = append(body, sty.muted.Render("↳ correctif/avis :"), "  "+linkLine(link, w-2, labelColor))
	}
	if len(body) == 0 {
		return nil
	}
	out := []string{sty.accent.Render("Que faire")}
	out = append(out, body...)
	return append(out, "")
}

// detailLines compose la fiche : titre, grille libellé/valeur, résumé,
// références.
func (m *ui) detailLines(a model.Advisory, w int) []string {
	var lines []string
	for _, l := range wrapLines(a.Title, w) {
		lines = append(lines, sty.bright.Render(l))
	}
	lines = append(lines, "")
	lines = append(lines, m.actionLines(a, w)...)

	valW := max(10, w-labelW-1)
	kv := func(label, val string) {
		if strings.TrimSpace(val) == "" {
			return
		}
		for i, l := range wrapLines(val, valW) {
			lead := strings.Repeat(" ", labelW)
			if i == 0 {
				lead = sty.id.Width(labelW).Render(label)
			}
			lines = append(lines, lead+" "+l)
		}
	}

	kv("ID", shortAliases(a.ExternalID, 8))
	src := sourceOf(a.Source)
	kv("Source", src.color+src.name+reset)
	if m.exploited(a) {
		kv("Exploitation", boldRed+"exploitée activement"+reset+dim+" · catalogue CISA KEV"+reset)
	}
	if sev := parseSeverity(a.Severity); sev.level > 0 {
		txt := bold + sev.color() + sev.label() + reset
		if sev.score != "" {
			txt += dim + " · CVSS " + sev.score + reset
		}
		kv("Sévérité", txt)
	} else if a.NVD.CVE != "" {
		nv := severity{level: a.NVD.Level}
		kv("Sévérité", bold+nv.color()+nv.label()+reset+dim+" · d'après NVD"+reset)
	} else if a.Source != "cisa-kev" && a.Source != "certfr" {
		kv("Sévérité", a.Severity)
	}
	if a.NVD.CVE != "" {
		kv("CVSS (NVD)", describeNVD(a.NVD, len(store.CVEs(a.ExternalID))))
	}
	if a.EPSS > 0 {
		kv("EPSS", describeEPSS(a.EPSS, a.EPSSPercentile))
	}
	kv("Composant", a.Component)
	if a.VulnType == "" && a.NVD.CWE != "" {
		kv("Type", describeCWEs(a.NVD.CWE)+dim+" (NVD)"+reset)
	} else {
		kv("Type", describeCWEs(a.VulnType))
	}
	kv("Versions affectées", a.AffectedVersions)
	if a.FixedVersions != "" {
		kv("Corrigé dans", sty.green.Render(a.FixedVersions))
	}
	kv("Remédiation", oneLine(shortRemediation(a.Remediation)))
	if !a.Published.IsZero() {
		kv("Publié", a.Published.Format("2006-01-02"))
	}
	for _, r := range m.certfrRefs(a) {
		kv("Avis CERT-FR", blue+r.ID+reset+" "+r.Title)
	}

	if a.Summary != "" {
		lines = append(lines, "")
		lines = append(lines, renderRich(a.Summary, w)...)
	}
	if ex := m.exploitsFor(a); len(ex) > 0 {
		lines = append(lines, "", boldRed+"Exploits publics"+reset+dim+" — à traiter en priorité"+reset)
		for _, e := range ex {
			tag := exploitKinds[e.Kind]
			line := sty.faint.Render("• ") + magenta + tag + reset + " " + e.Title
			lines = append(lines, wrapLines(line, w)...)
			lines = append(lines, "  "+linkLine(e.URL, w-2, labelColor))
		}
	}
	if len(a.References) > 0 {
		lines = append(lines, "", sty.id.Render("Références"))
		for _, r := range a.References {
			lines = append(lines, sty.faint.Render("• ")+linkLine(r, w-2, labelColor))
		}
	}
	return lines
}

// ---- aide ----

func (m *ui) helpView(w, h int) string {
	boxW := min(104, w)
	innerW := boxW - 4
	var lines []string
	for _, l := range helpLines() {
		l = colorHelpKey(l)
		if visibleLen(l) <= innerW {
			lines = append(lines, l)
		} else {
			lines = append(lines, wrapLines(l, innerW)...)
		}
	}
	rows := max(1, h-2-3)
	m.helpScr = max(0, min(m.helpScr, len(lines)-rows))
	right := ""
	if len(lines) > rows {
		right = sty.faint.Render(fmt.Sprintf("%d / %d", m.helpScr+1, len(lines)))
	}
	box := panel(boxW, h, true, "AIDE", right, lines[m.helpScr:], sty.faint.Render("┄ ↑↓ défiler · ? ou esc pour fermer"))
	return lipgloss.PlaceHorizontal(w, lipgloss.Center, box)
}

// shortAliases limite la liste d'alias affichée : « X (A, B, … et 42 autres) ».
func shortAliases(ext string, n int) string {
	id, rest, ok := strings.Cut(ext, " (")
	if !ok {
		return ext
	}
	aliases := strings.Split(strings.TrimSuffix(rest, ")"), ", ")
	if len(aliases) <= n {
		return ext
	}
	return fmt.Sprintf("%s (%s, … et %d autres)", id, strings.Join(aliases[:n], ", "), len(aliases)-n)
}

// helpKeyRe repère une ligne d'aide « touche/terme, au moins deux espaces,
// explication », pour colorer la première colonne.
var helpKeyRe = regexp.MustCompile(`^  (\S[^\x1b]*?)(\s{2,})(\S.*)$`)

// colorHelpKey met la touche (ou le filtre, le sigle) d'une ligne d'aide en
// couleur d'accent, l'explication restant neutre.
func colorHelpKey(l string) string {
	if strings.Contains(l, "\x1b") {
		return l // ligne déjà colorée (légende)
	}
	m := helpKeyRe.FindStringSubmatch(l)
	if m == nil || visibleLen(m[1]) > 18 {
		return l
	}
	return "  " + sty.key.Render(m[1]) + m[2] + m[3]
}

// overlayView affiche une fenêtre centrée défilante (sources…).
func (m *ui) overlayView(w, h int, title string, content []string, footer string) string {
	boxW := min(104, w)
	innerW := boxW - 4
	var lines []string
	for _, l := range content {
		if visibleLen(l) <= innerW {
			lines = append(lines, l)
		} else {
			lines = append(lines, wrapLines(l, innerW)...)
		}
	}
	rows := max(1, h-2-3)
	m.helpScr = max(0, min(m.helpScr, len(lines)-rows))
	box := panel(boxW, h, true, title, "", lines[m.helpScr:], sty.faint.Render(footer))
	return lipgloss.PlaceHorizontal(w, lipgloss.Center, box)
}

// epssHex donne la couleur de palette d'une probabilité EPSS (liste).
func epssHex(p float64) string {
	switch {
	case p >= 0.5:
		return pal.red
	case p >= 0.1:
		return pal.orange
	case p >= 0.01:
		return pal.yellow
	default:
		return pal.faint
	}
}
