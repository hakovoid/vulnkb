package tui

import (
	"os"
	"strings"

	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// palette : couleurs de la maquette (thème GitHub sombre), avec leur
// équivalent pour un terminal clair.
type palette struct {
	text, bright, muted, faint, border, selBg, onAccent              string
	accent, id, green, red, orange, yellow, gray, purple, blue, cyan string
	critBg, highBg, medBg, lowBg                                     string
}

var darkPalette = palette{
	text: "#c9d1d9", bright: "#e6edf3", muted: "#7d8590", faint: "#484f58",
	border: "#3d444d", selBg: "#1b2a3d", onAccent: "#0d1117",
	accent: "#58a6ff", id: "#58a6ff", green: "#3fb950", red: "#f85149",
	orange: "#f0883e", yellow: "#d29922", gray: "#8b949e", purple: "#bc8cff",
	blue: "#58a6ff", cyan: "#39c5cf",
	critBg: "#3d1d20", highBg: "#3d2616", medBg: "#3a2e12", lowBg: "#262b31",
}

var lightPalette = palette{
	text: "#1f2328", bright: "#0d1117", muted: "#59636e", faint: "#8c959f",
	border: "#d1d9e0", selBg: "#ddf4ff", onAccent: "#ffffff",
	accent: "#0969da", id: "#0969da", green: "#1a7f37", red: "#cf222e",
	orange: "#bc4c00", yellow: "#9a6700", gray: "#59636e", purple: "#8250df",
	blue: "#0969da", cyan: "#1b7c83",
	critBg: "#ffebe9", highBg: "#fff1e5", medBg: "#fff8c5", lowBg: "#eaeef2",
}

var pal = darkPalette

// Préfixes de couleur ANSI utilisés dans les textes composés (détail, aide).
// Valeurs de repli en 16 couleurs ; initTheme les remplace par la palette,
// convertie selon les capacités du terminal (16, 256 ou 16 M de couleurs).
var (
	red        = "\x1b[31m"
	boldRed    = "\x1b[1;31m"
	orange     = "\x1b[38;5;208m"
	yellow     = "\x1b[33m"
	magenta    = "\x1b[35m"
	blue       = "\x1b[34m"
	green      = "\x1b[32m"
	cyan       = "\x1b[36m"
	gray       = "\x1b[90m"
	labelColor = "\x1b[36m"
	titleColor = "\x1b[1;93m"
	inlineCode = "\x1b[38;5;180m"
)

// initTheme adapte la palette au terminal : fond clair ou sombre, nombre de
// couleurs, et couleur d'accent choisie par VULNKB_ACCENT.
func initTheme() {
	if !lipgloss.HasDarkBackground() {
		pal = lightPalette
		if os.Getenv("VULNKB_CODE_STYLE") == "" {
			codeStyle = styles.Get("github")
		}
	}
	if a := os.Getenv("VULNKB_ACCENT"); strings.HasPrefix(a, "#") && len(a) == 7 {
		pal.accent = a
	}
	profile := lipgloss.ColorProfile()
	if profile == termenv.TrueColor {
		codeFormatter = formatters.TTY16m
	}
	fg := func(hex string) string {
		seq := profile.Color(hex).Sequence(false)
		if seq == "" {
			return ""
		}
		return "\x1b[" + seq + "m"
	}
	red, orange, yellow, green = fg(pal.red), fg(pal.orange), fg(pal.yellow), fg(pal.green)
	magenta, blue, cyan, gray = fg(pal.purple), fg(pal.blue), fg(pal.cyan), fg(pal.gray)
	boldRed = bold + red
	labelColor = fg(pal.id)
	titleColor = bold + fg(pal.bright)
	inlineCode = fg(pal.orange)
	buildStyles()
}

// Styles Lipgloss des éléments de l'interface.
var sty styleSet

type styleSet struct {
	text, bright, muted, faint, accent, id, green lipgloss.Style
	badge                                         lipgloss.Style
	panel, panelFocus                             lipgloss.Style
	search, searchIdle                            lipgloss.Style
	selected                                      lipgloss.Style
	key                                           lipgloss.Style
}

func buildStyles() {
	c := func(hex string) lipgloss.Color { return lipgloss.Color(hex) }
	sty = styleSet{
		text:   lipgloss.NewStyle().Foreground(c(pal.text)),
		bright: lipgloss.NewStyle().Foreground(c(pal.bright)).Bold(true),
		muted:  lipgloss.NewStyle().Foreground(c(pal.muted)),
		faint:  lipgloss.NewStyle().Foreground(c(pal.faint)),
		accent: lipgloss.NewStyle().Foreground(c(pal.accent)).Bold(true),
		id:     lipgloss.NewStyle().Foreground(c(pal.id)),
		green:  lipgloss.NewStyle().Foreground(c(pal.green)).Bold(true),
		badge:  lipgloss.NewStyle().Bold(true).Width(10).Align(lipgloss.Center),
		panel: lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).
			BorderForeground(c(pal.border)).Padding(0, 1),
		panelFocus: lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).
			BorderForeground(c(pal.accent)).Padding(0, 1),
		search: lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).
			BorderForeground(c(pal.accent)).Padding(0, 1),
		searchIdle: lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).
			BorderForeground(c(pal.border)).Padding(0, 1),
		selected: lipgloss.NewStyle().Background(c(pal.selBg)),
		key:      lipgloss.NewStyle().Foreground(c(pal.accent)).Bold(true),
	}
}

func init() { buildStyles() }

// sevBadge rend l'étiquette de sévérité de la liste : « CRITIQUE » sur fond
// teinté, etc.
func sevBadge(level int) string {
	type b struct{ label, fg, bg string }
	badges := [...]b{
		{"—", pal.faint, ""},
		{"FAIBLE", pal.gray, pal.lowBg},
		{"MOYEN", pal.yellow, pal.medBg},
		{"ÉLEVÉ", pal.orange, pal.highBg},
		{"CRITIQUE", pal.red, pal.critBg},
	}
	x := badges[level]
	s := sty.badge.Foreground(lipgloss.Color(x.fg))
	if x.bg != "" {
		s = s.Background(lipgloss.Color(x.bg))
	}
	return s.Render(x.label)
}
