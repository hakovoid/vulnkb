// Package tui est l'interface de consultation en terminal, construite avec
// Bubble Tea (boucle d'événements) et Lipgloss (mise en forme) : barre de
// recherche, liste des résultats, fiche détaillée, aide.
package tui

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"vulnkb/internal/model"
	"vulnkb/internal/store"
)

// window est le nombre de résultats gardés en mémoire autour de la position
// courante ; le reste est relu en base à la demande.
const window = 200

type ui struct {
	st      *store.Store
	input   textinput.Model
	query   string           // saisie pour laquelle les résultats sont chargés
	results []model.Advisory // résultats de rang offset à offset+len-1
	offset  int
	matches int // nombre total de résultats de la recherche
	cursor  int // rang absolu de l'entrée sélectionnée
	top     int // rang de la première ligne affichée
	total   int
	seq     int // numéro de la dernière recherche lancée

	width, height int
	listH         int // lignes de résultats visibles
	detail        viewport.Model
	detailID      string // entrée affichée dans le détail
	detailW       int

	splitPct int        // largeur du panneau liste, en % (disposition côte à côte)
	sort     store.Sort // ordre des résultats
	detFocus bool       // Tab : flèches pour le détail
	zoom     bool       // Entrée : fiche en plein écran
	help     bool
	helpScr  int
	srcView  bool     // fenêtre des sources (Alt-S) ou des statistiques (Alt-I)
	srcLines []string // contenu de cette fenêtre
	srcTitle string   // « SOURCES » ou « STATISTIQUES »
	gotoMode bool
	gotoBuf  string
	theme    string // thème de couleurs courant
	mouseOff bool   // souris laissée au terminal (clic sur les liens, sélection)
	flash    string // message bref affiché dans la barre de statut

	lastSync time.Time
	dbSize   int64
	kev      map[string][]store.Ref // CVE -> entrées CISA KEV
	certfr   map[string][]store.Ref // CVE -> avis CERT-FR

	syncSearch bool // tests : recherche exécutée sans passer par une commande
}

// Run lance l'interface et rend la main à la sortie (Esc ou Ctrl-C).
func Run(st *store.Store) error {
	name := os.Getenv("VULNKB_THEME")
	if name == "" {
		name, _ = st.Meta(ThemeMetaKey)
	}
	applied := initTheme(name)
	m := newUI(st)
	m.theme = applied
	opts := []tea.ProgramOption{tea.WithAltScreen()}
	if os.Getenv("VULNKB_MOUSE") == "0" {
		m.mouseOff = true
	} else {
		opts = append(opts, tea.WithMouseCellMotion())
	}
	_, err := tea.NewProgram(m, opts...).Run()
	return err
}

// splitMin / splitMax bornent la largeur du panneau liste (en %).
const (
	splitMin     = 25
	splitMax     = 70
	splitDefault = 42
)

func newUI(st *store.Store) *ui {
	in := textinput.New()
	in.Prompt = ""
	in.Placeholder = "CVE, produit, CWE, mot-clé… (? pour l'aide)"
	in.Focus()

	m := &ui{st: st, input: in, detail: viewport.New(0, 0), splitPct: splitDefault, theme: themes[0].name}
	m.styleInput()
	m.total, _ = st.CountMatches("")
	m.kev, _ = st.CVEIndex("cisa-kev")
	m.certfr, _ = st.CVEIndex("certfr")
	m.lastSync, _ = st.LastSync()
	m.dbSize, _ = st.DBSize()
	m.applySearch(runSearch(st, 0, "", store.SortAuto))
	return m
}

// ThemeMetaKey est la clé sous laquelle le thème choisi est mémorisé en base.
const ThemeMetaKey = "theme"

// styleInput applique le thème courant au champ de recherche.
func (m *ui) styleInput() {
	m.input.PlaceholderStyle = sty.muted
	m.input.TextStyle = sty.bright.UnsetBold()
	m.input.Cursor.Style = sty.accent
}

// cycleTheme passe au thème suivant, le mémorise et recompose l'affichage.
func (m *ui) cycleTheme() {
	m.theme = applyTheme(nextTheme(m.theme))
	m.styleInput()
	m.detailID = "" // la fiche contient des couleurs : à recomposer
	m.st.SetMeta(ThemeMetaKey, m.theme)
	m.flash = "thème " + m.theme
}

// statsDone apporte le rapport statistique calculé en arrière-plan.
type statsDone []string

// exportDone signale la fin d'un export HTML lancé en arrière-plan.
type exportDone struct {
	path string
	err  error
}

func (m *ui) exportCmd(run func() (string, error)) tea.Cmd {
	return func() tea.Msg {
		p, err := run()
		return exportDone{p, err}
	}
}

// ---- recherche ----

type searchResult struct {
	seq     int
	query   string
	matches int
	results []model.Advisory
}

func runSearch(s *store.Store, seq int, q string, sort store.Sort) searchResult {
	r := searchResult{seq: seq, query: q}
	r.matches, _ = s.CountMatches(q)
	r.results, _ = s.SearchPageSorted(q, sort, 0, window)
	return r
}

// searchCmd lance la recherche en arrière-plan : l'écran reste réactif
// pendant une requête lente, et une réponse périmée est ignorée.
func (m *ui) searchCmd() tea.Cmd {
	m.seq++
	seq, q, s, sort := m.seq, m.input.Value(), m.st, m.sort
	if m.syncSearch {
		m.applySearch(runSearch(s, seq, q, sort))
		return nil
	}
	return func() tea.Msg { return runSearch(s, seq, q, sort) }
}

func (m *ui) applySearch(r searchResult) {
	if r.seq != m.seq {
		return
	}
	m.query, m.matches, m.results = r.query, r.matches, r.results
	m.cursor, m.top, m.offset = 0, 0, 0
	m.detailID = ""
}

func (m *ui) fetchWindow(offset int) {
	res, err := m.st.SearchPageSorted(m.query, m.sort, offset, window)
	if err != nil {
		res = nil
	}
	m.offset, m.results = offset, res
}

// current renvoie l'entrée sélectionnée.
func (m *ui) current() (model.Advisory, bool) {
	i := m.cursor - m.offset
	if i < 0 || i >= len(m.results) {
		return model.Advisory{}, false
	}
	return m.results[i], true
}

// setCursor place la sélection au rang n (borné aux résultats).
func (m *ui) setCursor(n int) {
	m.cursor = max(0, min(n, m.matches-1))
	m.ensureVisible()
}

// ensureVisible fait défiler la liste pour montrer la sélection, et recharge
// la fenêtre en mémoire si les lignes à afficher en sortent.
func (m *ui) ensureVisible() {
	h := max(1, m.listH)
	if m.cursor < m.top {
		m.top = m.cursor
	}
	if m.cursor >= m.top+h {
		m.top = m.cursor - h + 1
	}
	m.top = max(0, min(m.top, m.matches-h))
	end := min(m.top+h, m.matches)
	if m.top < m.offset || end > m.offset+len(m.results) {
		m.fetchWindow(max(0, m.top-(window-h)/2))
	}
}

// exploited indique si l'entrée, ou l'un de ses CVE, figure au catalogue KEV.
func (m *ui) exploited(a model.Advisory) bool {
	if a.Source == "cisa-kev" {
		return true
	}
	for _, c := range store.CVEs(a.ExternalID) {
		if len(m.kev[c]) > 0 {
			return true
		}
	}
	return false
}

// exploitsFor renvoie les exploits publics liés aux CVE de l'entrée.
func (m *ui) exploitsFor(a model.Advisory) []model.ExploitRef {
	cves := store.CVEs(a.ExternalID)
	if len(cves) == 0 {
		return nil
	}
	ex, _ := m.st.ExploitsFor(cves)
	return ex
}

// certfrRefs renvoie les avis CERT-FR qui citent un CVE de l'entrée.
func (m *ui) certfrRefs(a model.Advisory) []store.Ref {
	if a.Source == "certfr" {
		return nil
	}
	seen := map[string]bool{}
	var out []store.Ref
	for _, c := range store.CVEs(a.ExternalID) {
		for _, r := range m.certfr[c] {
			if !seen[r.ID] {
				seen[r.ID] = true
				out = append(out, r)
			}
		}
	}
	return out
}

// ---- boucle Bubble Tea ----

func (m *ui) Init() tea.Cmd { return textinput.Blink }

func (m *ui) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		return m, nil
	case statsDone:
		if m.srcView && m.srcTitle == "STATISTIQUES" {
			m.srcLines = msg
		}
		return m, nil
	case exportDone:
		if msg.err != nil {
			m.flash = "export impossible : " + msg.err.Error()
		} else {
			m.flash = "exporté : " + msg.path
		}
		return m, nil
	case searchResult:
		m.applySearch(msg)
		m.layout()
		return m, nil
	case tea.MouseMsg:
		m.handleMouse(msg)
		m.syncDetail()
		return m, nil
	case tea.KeyMsg:
		cmd := m.handleKey(msg)
		m.syncDetail()
		return m, cmd
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

// handleMouse gère la molette (défilement) et le glissé sur la séparation des
// panneaux (redimensionnement).
func (m *ui) handleMouse(e tea.MouseMsg) {
	if m.srcView {
		if e.Button == tea.MouseButtonWheelUp {
			m.helpScr = max(0, m.helpScr-3)
		} else if e.Button == tea.MouseButtonWheelDown {
			m.helpScr += 3
		}
		return
	}
	if m.help || m.zoom {
		if e.Button == tea.MouseButtonWheelUp {
			m.detail.LineUp(3)
		} else if e.Button == tea.MouseButtonWheelDown {
			m.detail.LineDown(3)
		}
		return
	}
	g := m.geometry()
	overDetail := !g.stacked && g.listW > 0 && e.X > g.listW
	switch e.Button {
	case tea.MouseButtonWheelUp:
		if overDetail {
			m.detail.LineUp(3)
		} else {
			m.setCursor(m.cursor - 3)
		}
		return
	case tea.MouseButtonWheelDown:
		if overDetail {
			m.detail.LineDown(3)
		} else {
			m.setCursor(m.cursor + 3)
		}
		return
	}
	// glissé gauche sur/près de la séparation → nouvelle largeur
	if g.stacked || g.listW == 0 || e.Button != tea.MouseButtonLeft {
		return
	}
	if e.Action == tea.MouseActionPress && abs(e.X-g.listW) > 2 {
		return // clic ailleurs : on ne redimensionne pas
	}
	if e.Action == tea.MouseActionPress || e.Action == tea.MouseActionMotion {
		m.setSplit(e.X * 100 / max(1, m.width))
	}
}

// setSplit fixe la largeur du panneau liste (en %), bornée, et recompose.
func (m *ui) setSplit(pct int) {
	pct = max(splitMin, min(splitMax, pct))
	if pct != m.splitPct {
		m.splitPct = pct
		m.layout()
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// keyAliases fait accepter Alt partout où l'application utilise Ctrl :
// certains terminaux, dont celui de VS Code, gardent des Ctrl pour eux
// (Ctrl-G = « aller à la ligne »…).
var keyAliases = map[string]string{
	"alt+g": "ctrl+g", "alt+t": "ctrl+t", "alt+o": "ctrl+o", "alt+y": "ctrl+y",
	"alt+left": "ctrl+left", "alt+right": "ctrl+right",
}

func (m *ui) handleKey(k tea.KeyMsg) tea.Cmd {
	m.flash = ""
	key := k.String()
	if alias, ok := keyAliases[key]; ok {
		key = alias
	}
	if key == "ctrl+c" {
		return tea.Quit
	}
	switch {
	case m.srcView:
		switch key {
		case "esc", "alt+s", "alt+i", "q":
			m.srcView = false
		case "up":
			m.helpScr = max(0, m.helpScr-1)
		case "down":
			m.helpScr++
		}
		return nil
	case m.help:
		m.helpKey(key)
		return nil
	case m.gotoMode:
		m.gotoKey(k)
		return nil
	}

	switch key {
	case "esc":
		if m.zoom {
			m.zoom = false
			m.layout()
			return nil
		}
		return tea.Quit
	case "?":
		m.help, m.helpScr = true, 0
		return nil
	case "alt+e":
		if a, ok := m.current(); ok {
			m.flash = "export de la fiche…"
			return m.exportCmd(func() (string, error) { return ExportAdvisory(m.st, a, "") })
		}
		return nil
	case "alt+r":
		q, sort := m.query, m.sort
		m.flash = "export du rapport…"
		return m.exportCmd(func() (string, error) {
			path, n, total, err := ExportSearch(m.st, q, sort, exportMax, "")
			if err == nil && total > n {
				path += fmt.Sprintf("  (%s fiches sur %s)", fmtInt(n), fmtInt(total))
			}
			return path, err
		})
	case "alt+s":
		m.srcView, m.helpScr, m.srcTitle, m.srcLines = true, 0, "SOURCES", SourceReport(m.st)
		return nil
	case "alt+i":
		m.srcView, m.helpScr, m.srcTitle = true, 0, "STATISTIQUES"
		m.srcLines = []string{dim + "calcul des statistiques…" + reset}
		st := m.st
		return func() tea.Msg { return statsDone(StatsReport(st)) }
	case "ctrl+g":
		m.gotoMode, m.gotoBuf = true, ""
		return nil
	case "tab", "shift+tab":
		m.detFocus = !m.detFocus
		return nil
	case "enter":
		m.zoom = !m.zoom
		m.layout()
		return nil
	case "up", "down", "pgup", "pgdown", "home", "end":
		m.navigate(key)
		return nil
	case "ctrl+left":
		m.setSplit(m.splitPct - 4)
		return nil
	case "ctrl+right":
		m.setSplit(m.splitPct + 4)
		return nil
	case "ctrl+o":
		m.sort = store.NextSort(m.sort) // pertinence → date → criticité → EPSS
		return m.searchCmd()
	case "ctrl+y":
		m.cycleTheme()
		return nil
	case "alt+m":
		m.mouseOff = !m.mouseOff
		if m.mouseOff {
			m.flash = "souris rendue au terminal : clic sur les liens et sélection de texte"
			return tea.DisableMouse
		}
		m.flash = "souris active : molette et redimensionnement"
		return tea.EnableMouseCellMotion
	case "ctrl+t":
		m.input.SetValue(toggleWord(m.input.Value(), "mes"))
		m.input.CursorEnd()
		return m.searchCmd()
	}

	before := m.input.Value()
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(k)
	if m.input.Value() != before {
		return tea.Batch(cmd, m.searchCmd())
	}
	return cmd
}

// navigate déplace la sélection, ou fait défiler la fiche quand elle a le
// focus (Tab) ou qu'elle est en plein écran (Entrée).
func (m *ui) navigate(key string) {
	if m.detFocus || m.zoom {
		switch key {
		case "up":
			m.detail.LineUp(1)
		case "down":
			m.detail.LineDown(1)
		case "pgup":
			m.detail.HalfViewUp()
		case "pgdown":
			m.detail.HalfViewDown()
		case "home":
			m.detail.GotoTop()
		case "end":
			m.detail.GotoBottom()
		}
		return
	}
	page := max(1, m.listH-1)
	switch key {
	case "up":
		m.setCursor(m.cursor - 1)
	case "down":
		m.setCursor(m.cursor + 1)
	case "pgup":
		m.setCursor(m.cursor - page)
	case "pgdown":
		m.setCursor(m.cursor + page)
	case "home":
		m.setCursor(0)
	case "end":
		m.setCursor(m.matches - 1)
	}
}

func (m *ui) helpKey(key string) {
	switch key {
	case "esc", "?", "q":
		m.help = false
	case "up":
		m.helpScr = max(0, m.helpScr-1)
	case "down":
		m.helpScr++
	case "pgup":
		m.helpScr = max(0, m.helpScr-10)
	case "pgdown":
		m.helpScr += 10
	case "home":
		m.helpScr = 0
	}
}

// gotoKey gère la saisie du numéro d'entrée après Ctrl-G.
func (m *ui) gotoKey(k tea.KeyMsg) {
	switch k.String() {
	case "esc":
		m.gotoMode = false
	case "enter":
		m.gotoMode = false
		if n, err := strconv.Atoi(m.gotoBuf); err == nil && n >= 1 {
			m.detFocus, m.zoom = false, false
			m.top = n - 1 - m.listH/2 // centre l'entrée à l'écran
			m.setCursor(n - 1)
		}
	case "backspace":
		if m.gotoBuf != "" {
			m.gotoBuf = m.gotoBuf[:len(m.gotoBuf)-1]
		}
	default:
		for _, r := range k.Runes {
			if r >= '0' && r <= '9' && len(m.gotoBuf) < 9 {
				m.gotoBuf += string(r)
			}
		}
	}
}

// syncAge présente l'ancienneté de la dernière synchro : « il y a 2 h ».
func syncAge(t time.Time, now time.Time) string {
	if t.IsZero() {
		return "jamais synchronisé"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "à l'instant"
	case d < time.Hour:
		return fmt.Sprintf("il y a %d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("il y a %d h", int(d.Hours()))
	default:
		return fmt.Sprintf("il y a %d j", int(d.Hours()/24))
	}
}

// oneLine remplace les sauts de ligne d'un titre par des espaces.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// toggleWord ajoute word en tête de la saisie s'il n'y figure pas, ou le
// retire s'il y est déjà (bascule du filtre « mes » par Ctrl-T).
func toggleWord(s, word string) string {
	fields := strings.Fields(s)
	kept := fields[:0]
	found := false
	for _, f := range fields {
		if strings.EqualFold(f, word) {
			found = true
			continue
		}
		kept = append(kept, f)
	}
	if found {
		return strings.Join(kept, " ")
	}
	return strings.TrimSpace(word + " " + strings.Join(kept, " "))
}
