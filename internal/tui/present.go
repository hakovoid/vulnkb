package tui

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

const (
	red     = "\x1b[31m"
	boldRed = "\x1b[1;31m"
	orange  = "\x1b[38;5;208m"
	yellow  = "\x1b[33m"
	magenta = "\x1b[35m"
	blue    = "\x1b[34m"
	green   = "\x1b[32m"
	gray    = "\x1b[90m"
)

// severity est une gravité ramenée à une échelle commune, quelle que soit la
// façon dont la source l'exprime (libellé, vecteur CVSS…).
type severity struct {
	level int    // 4 critique … 1 faible, 0 inconnue
	score string // score CVSS calculé, si la source ne donne qu'un vecteur
}

var sevLevels = map[string]int{"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}

func parseSeverity(raw string) severity {
	raw = strings.TrimSpace(raw)
	if l, ok := sevLevels[strings.ToUpper(raw)]; ok {
		return severity{level: l}
	}
	if score, ok := cvss3Score(raw); ok {
		return severity{level: levelForScore(score), score: fmt.Sprintf("%.1f", score)}
	}
	return severity{}
}

func levelForScore(s float64) int {
	switch {
	case s >= 9:
		return 4
	case s >= 7:
		return 3
	case s >= 4:
		return 2
	case s > 0:
		return 1
	}
	return 0
}

func (s severity) color() string {
	return [...]string{gray, gray, yellow, orange, red}[s.level]
}

// short est le libellé de la colonne de liste (4 caractères).
func (s severity) short() string {
	return [...]string{" ·  ", "LOW ", "MED ", "HIGH", "CRIT"}[s.level]
}

func (s severity) label() string {
	return [...]string{"inconnue", "Faible", "Moyenne", "Élevée", "Critique"}[s.level]
}

// cvss3Score calcule le score de base d'un vecteur CVSS 3.0/3.1
// (spécification FIRST, section 7).
func cvss3Score(vector string) (float64, bool) {
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return 0, false
	}
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}
	changed := m["S"] == "C"
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	ac := map[string]float64{"L": 0.77, "H": 0.44}
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		pr["L"], pr["H"] = 0.68, 0.5
	}
	ui := map[string]float64{"N": 0.85, "R": 0.62}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

	get := func(tbl map[string]float64, k string) (float64, bool) {
		v, ok := tbl[m[k]]
		return v, ok
	}
	vals := make([]float64, 0, 7)
	for _, p := range []struct {
		tbl map[string]float64
		key string
	}{{av, "AV"}, {ac, "AC"}, {pr, "PR"}, {ui, "UI"}, {cia, "C"}, {cia, "I"}, {cia, "A"}} {
		v, ok := get(p.tbl, p.key)
		if !ok {
			return 0, false
		}
		vals = append(vals, v)
	}

	iss := 1 - (1-vals[4])*(1-vals[5])*(1-vals[6])
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}
	expl := 8.22 * vals[0] * vals[1] * vals[2] * vals[3]
	if changed {
		return roundUp(math.Min(1.08*(impact+expl), 10)), true
	}
	return roundUp(math.Min(impact+expl, 10)), true
}

// roundUp est l'arrondi supérieur à une décimale défini par CVSS 3.1.
func roundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}

type sourceInfo struct {
	badge, color, name string
}

var sources = map[string]sourceInfo{
	"cisa-kev":   {"KEV", boldRed, "CISA KEV (failles exploitées activement)"},
	"osv":        {"OSV", green, "OSV.dev (paquets open source)"},
	"article-ia": {"IA ", magenta, "article, fiche extraite par IA (à relire)"},
	"certfr":     {"FR ", blue, "CERT-FR (ANSSI), en français"},
}

func sourceOf(name string) sourceInfo {
	if s, ok := sources[name]; ok {
		return s
	}
	b := strings.ToUpper(name)
	if len(b) > 3 {
		b = b[:3]
	}
	return sourceInfo{fmt.Sprintf("%-3s", b), gray, name}
}

var (
	fenceRe   = regexp.MustCompile("(?m)^\\s*```.*$\n?")
	headingRe = regexp.MustCompile(`(?m)^#{1,6}\s+(.+?)\s*#*\s*$`)
	boldMdRe  = regexp.MustCompile(`\*\*(.+?)\*\*|__(.+?)__`)
	codeRe    = regexp.MustCompile("`([^`]+)`")
	linkRe    = regexp.MustCompile(`!?\[([^\[\]\n]*)\]\(([^)\s]+)\)`)
	bulletRe  = regexp.MustCompile(`(?m)^(\s*)[-*+]\s+`)
	htmlTagRe = regexp.MustCompile(`</?[a-zA-Z][^>]*>`)
	blanksRe  = regexp.MustCompile(`\n{3,}`)
)

// cleanMarkdown rend lisible en terminal le Markdown des résumés OSV.
func cleanMarkdown(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = fenceRe.ReplaceAllString(s, "")
	s = linkRe.ReplaceAllStringFunc(s, func(m string) string {
		p := linkRe.FindStringSubmatch(m)
		if p[1] == "" || p[1] == p[2] {
			return p[2]
		}
		return p[1] + " (" + p[2] + ")"
	})
	s = boldMdRe.ReplaceAllString(s, "$1$2")
	s = codeRe.ReplaceAllString(s, "$1")
	s = htmlTagRe.ReplaceAllString(s, "")
	s = headingRe.ReplaceAllString(s, bold+"$1"+reset)
	s = bulletRe.ReplaceAllString(s, "$1• ")
	return strings.TrimSpace(blanksRe.ReplaceAllString(s, "\n\n"))
}

var cweRe = regexp.MustCompile(`CWE-\d+`)

// describeCWEs ajoute le nom de chaque CWE connue : « CWE-79 (XSS) ».
func describeCWEs(s string) string {
	return cweRe.ReplaceAllStringFunc(s, func(id string) string {
		if name, ok := cweNames[id]; ok {
			return id + " (" + name + ")"
		}
		return id
	})
}

// primaryID est l'identifiant principal, sans la liste d'alias entre parenthèses.
func primaryID(externalID string) string {
	if i := strings.Index(externalID, " ("); i > 0 {
		return externalID[:i]
	}
	return externalID
}
