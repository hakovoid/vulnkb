// Package tui est l'interface de consultation en terminal, construite avec
// Bubble Tea (boucle d'événements) et Lipgloss (mise en forme) : barre de
// recherche, liste des résultats, fiche détaillée, aide.
package tui

import (
	"fmt"
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

	detFocus bool // Tab : flèches pour le détail
	zoom     bool // Entrée : fiche en plein écran
	help     bool
	helpScr  int
	gotoMode bool
	gotoBuf  string

	lastSync time.Time
	kev      map[string][]store.Ref // CVE -> entrées CISA KEV
	certfr   map[string][]store.Ref // CVE -> avis CERT-FR

	syncSearch bool // tests : recherche exécutée sans passer par une commande
}

// Run lance l'interface et rend la main à la sortie (Esc ou Ctrl-C).
func Run(st *store.Store) error {
	initTheme()
	m := newUI(st)
	_, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func newUI(st *store.Store) *ui {
	in := textinput.New()
	in.Prompt = ""
	in.Placeholder = "CVE, produit, CWE, mot-clé… (? pour l'aide)"
	in.PlaceholderStyle = sty.muted
	in.TextStyle = sty.bright.UnsetBold()
	in.Cursor.Style = sty.accent
	in.Focus()

	m := &ui{st: st, input: in, detail: viewport.New(0, 0)}
	m.total, _ = st.CountMatches("")
	m.kev, _ = st.CVEIndex("cisa-kev")
	m.certfr, _ = st.CVEIndex("certfr")
	m.lastSync, _ = st.LastSync()
	m.applySearch(runSearch(st, 0, ""))
	return m
}

// ---- recherche ----

type searchResult struct {
	seq     int
	query   string
	matches int
	results []model.Advisory
}

func runSearch(s *store.Store, seq int, q string) searchResult {
	r := searchResult{seq: seq, query: q}
	r.matches, _ = s.CountMatches(q)
	r.results, _ = s.SearchPage(q, 0, window)
	return r
}

// searchCmd lance la recherche en arrière-plan : l'écran reste réactif
// pendant une requête lente, et une réponse périmée est ignorée.
func (m *ui) searchCmd() tea.Cmd {
	m.seq++
	seq, q, s := m.seq, m.input.Value(), m.st
	if m.syncSearch {
		m.applySearch(runSearch(s, seq, q))
		return nil
	}
	return func() tea.Msg { return runSearch(s, seq, q) }
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
	res, err := m.st.SearchPage(m.query, offset, window)
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
	case searchResult:
		m.applySearch(msg)
		m.layout()
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

func (m *ui) handleKey(k tea.KeyMsg) tea.Cmd {
	key := k.String()
	if key == "ctrl+c" {
		return tea.Quit
	}
	switch {
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
