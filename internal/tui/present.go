package tui

import (
	"fmt"
	"regexp"
	"strings"

	"vulnkb/internal/model"
	"vulnkb/internal/store"
)

// severity est la gravité normalisée (voir model.ParseSeverity), avec ses
// attributs d'affichage.
type severity struct {
	level int
	score string
}

func parseSeverity(raw string) severity {
	s := model.ParseSeverity(raw)
	return severity{level: s.Level, score: s.Score}
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

// effectiveSeverity est la sévérité donnée par la source, ou à défaut celle
// du score NVD de ses CVE.
func effectiveSeverity(a model.Advisory) severity {
	if s := parseSeverity(a.Severity); s.level > 0 {
		return s
	}
	return severity{level: a.NVD.Level}
}

// describeNVD présente un score NVD : « 9.8 · CVSS 3.1 · CVE-… · vecteur ».
func describeNVD(c model.CVSS, nCVEs int) string {
	s := severity{level: c.Level}
	txt := s.color() + bold + fmt.Sprintf("%.1f", c.Score) + reset + dim + " · CVSS " + c.Version + " · " + c.CVE
	if nCVEs > 1 {
		txt += fmt.Sprintf(" (le plus élevé de %d CVE)", nCVEs)
	}
	if c.Source != "" && c.Source != "nvd@nist.gov" {
		txt += " · évalué par " + c.Source
	}
	if c.Vector != "" {
		txt += " · " + c.Vector
	}
	return txt + reset
}

// describeFilters résume les filtres reconnus dans la saisie, pour que
// l'utilisateur voie ce qui est réellement appliqué.
func describeFilters(q store.Query) string {
	var parts []string
	if len(q.Severities) > 0 {
		var names []string
		for _, l := range q.Severities {
			s := severity{level: l}
			names = append(names, s.color()+strings.ToLower(s.label())+reset+dim)
		}
		parts = append(parts, "sévérité "+strings.Join(names, ", "))
	}
	if len(q.Sources) > 0 {
		var names []string
		for _, s := range q.Sources {
			info := sourceOf(s)
			names = append(names, info.color+strings.TrimSpace(info.badge)+reset+dim)
		}
		parts = append(parts, "source "+strings.Join(names, ", "))
	}
	if q.Exploited {
		parts = append(parts, boldRed+"exploitées"+reset+dim)
	}
	out := ""
	if len(parts) > 0 {
		out = dim + "   filtres : " + strings.Join(parts, " · ") + reset
	}
	if len(q.Invalid) > 0 {
		out += "   " + red + "filtre non reconnu : " + strings.Join(q.Invalid, " ") + reset + dim + " (? aide)" + reset
	}
	return out
}

type sourceInfo struct {
	badge, color, name string
}

var sources = map[string]sourceInfo{
	"cisa-kev":   {"KEV", boldRed, "CISA KEV (failles exploitées activement)"},
	"osv":        {"OSV", green, "OSV.dev (paquets open source)"},
	"article-ia": {"IA ", magenta, "article, fiche extraite par IA (à relire)"},
	"certfr":     {"FR ", blue, "CERT-FR (ANSSI), en français"},
	"nvd":        {"NVD", cyan, "NVD (base CVE du NIST)"},
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
	s = codeRe.ReplaceAllString(s, inlineCode+"$1"+reset)
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
