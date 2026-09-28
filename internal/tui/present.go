package tui

import (
	"fmt"
	"regexp"
	"strings"

	"vulnkb/internal/cvelist"
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

var (
	refAggregators = []string{"nvd.nist.gov", "cve.org", "cve.mitre.org", "osv.dev", "first.org", "cisa.gov/known-exploited"}
	refFixHints    = []string{"/commit/", "/releases/", "/security/", "advisor", "bulletin", "/patch", "/support/", "/kb/", "/hc/", "security-update", "release-notes"}
)

// fixLink choisit, parmi les références, le lien le plus utile pour corriger :
// un avis éditeur ou un correctif de préférence, en écartant les agrégateurs
// (NVD, CVE.org, OSV…). Renvoie "" si seuls des agrégateurs sont présents.
func fixLink(refs []string) string {
	var fallback string
	for _, r := range refs {
		low := strings.ToLower(r)
		if containsAny(low, refAggregators) {
			continue
		}
		for _, h := range refFixHints {
			if strings.Contains(low, h) {
				return r
			}
		}
		if fallback == "" {
			fallback = r
		}
	}
	return fallback
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// fmtPct présente une probabilité (0 à 1) en pourcentage français :
// « 94 % », « 3,2 % », « 0,04 % ».
func fmtPct(p float64) string {
	v := p * 100
	var t string
	switch {
	case v >= 10:
		t = fmt.Sprintf("%.0f", v)
	case v >= 1:
		t = fmt.Sprintf("%.1f", v)
	default:
		t = fmt.Sprintf("%.2f", v)
	}
	return strings.Replace(t, ".", ",", 1) + " %"
}

// fmtPctile présente un centile : une décimale près du sommet, pour ne pas
// arrondir 99,8 % à « 100 % ».
func fmtPctile(p float64) string {
	if v := p * 100; v >= 99 && v < 100 {
		return strings.Replace(fmt.Sprintf("%.1f", v), ".", ",", 1) + " %"
	}
	return fmtPct(p)
}

// epssColor gradue la couleur d'une probabilité EPSS.
func epssColor(p float64) string {
	switch {
	case p >= 0.5:
		return red
	case p >= 0.1:
		return orange
	case p >= 0.01:
		return yellow
	default:
		return gray
	}
}

// describeEPSS présente le score EPSS d'une entrée pour la fiche.
func describeEPSS(p, pct float64) string {
	return bold + epssColor(p) + fmtPct(p) + reset + dim + " de probabilité d'exploitation sous 30 jours · plus menaçant que " +
		fmtPctile(pct) + " des CVE" + reset
}

// describeSSVC résume l'évaluation SSVC de la CISA : exploitation constatée,
// automatisable, impact technique. "" si absente.
func describeSSVC(v cvelist.SSVC) string {
	var expl string
	switch v.Exploitation {
	case "active":
		expl = boldRed + "exploitation constatée" + reset
	case "poc":
		expl = magenta + "preuve de concept publique" + reset
	case "none":
		expl = "pas d'exploitation connue"
	default:
		return ""
	}
	parts := []string{expl}
	switch v.Automatable {
	case "yes":
		parts = append(parts, orange+"automatisable"+reset)
	case "no":
		parts = append(parts, "non automatisable")
	}
	switch v.Impact {
	case "total":
		parts = append(parts, "impact total")
	case "partial":
		parts = append(parts, "impact partiel")
	}
	return strings.Join(parts, dim+" · "+reset)
}

// exploitKinds nomme les origines d'exploit dans la fiche.
var exploitKinds = map[string]string{
	"msf": "Metasploit", "edb": "Exploit-DB", "poc": "PoC GitHub",
}

// shortRemediation remplace le long paragraphe générique de CISA KEV (« Apply
// mitigations in accordance with vendor instructions… BOD 26-04… ») par une
// consigne courte en français ; les autres remédiations sont laissées telles
// quelles.
func shortRemediation(s string) string {
	if strings.Contains(s, "BOD ") && strings.Contains(s, "vendor instructions") {
		return "Appliquer les correctifs ou mesures de l'éditeur (voir Références) ; à défaut, cesser d'utiliser le produit."
	}
	return s
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
	if q.Exploit {
		parts = append(parts, magenta+"exploit public"+reset+dim)
	}
	if q.EPSSMin > 0 {
		parts = append(parts, orange+"EPSS ≥ "+fmtPct(q.EPSSMin)+reset+dim)
	}
	if q.WatchReq && len(q.Watch) > 0 {
		parts = append(parts, sty.accent.Render("surveillés")+dim+fmt.Sprintf(" (%d)", len(q.Watch)))
	}
	out := ""
	if len(parts) > 0 {
		out = dim + "   filtres : " + strings.Join(parts, " · ") + reset
	}
	if q.WatchReq && len(q.Watch) == 0 {
		out += "   " + red + "liste de surveillance vide" + reset + dim + " (vulnkb watch add …)" + reset
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
