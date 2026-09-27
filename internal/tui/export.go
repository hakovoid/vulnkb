package tui

import (
	"fmt"
	"html"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"vulnkb/internal/model"
	"vulnkb/internal/store"
)

// exportMax borne le nombre de fiches d'un rapport HTML.
const exportMax = 1000

// ExportDir est le dossier des exports : VULNKB_EXPORT_DIR, sinon
// ~/vulnkb-exports.
func ExportDir() string {
	if d := os.Getenv("VULNKB_EXPORT_DIR"); d != "" {
		return d
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "vulnkb-exports")
	}
	return "vulnkb-exports"
}

// ExportSearch écrit un rapport HTML des résultats de la recherche query
// (au plus max fiches, dans l'ordre sort) ; renvoie le chemin du fichier, le
// nombre de fiches exportées et le nombre total de résultats.
func ExportSearch(st *store.Store, query string, sort store.Sort, max int, path string) (string, int, int, error) {
	if max <= 0 || max > exportMax {
		max = exportMax
	}
	total, err := st.CountMatches(query)
	if err != nil {
		return "", 0, 0, err
	}
	advs, err := st.SearchPageSorted(query, sort, 0, max)
	if err != nil {
		return "", 0, 0, err
	}
	if len(advs) == 0 {
		return "", 0, total, fmt.Errorf("aucun résultat à exporter")
	}
	title := "Recherche « " + query + " »"
	if strings.TrimSpace(query) == "" {
		title = "Toute la base"
	}
	if path == "" {
		path = exportPath(query)
	}
	err = writeExport(st, path, advs, reportMeta{Title: title, Query: query, Sort: store.SortLabel(sort), Total: total})
	return path, len(advs), total, err
}

// ExportAdvisory écrit la fiche a seule dans un fichier HTML.
func ExportAdvisory(st *store.Store, a model.Advisory, path string) (string, error) {
	if path == "" {
		path = exportPath(primaryID(a.ExternalID))
	}
	return path, writeExport(st, path, []model.Advisory{a}, reportMeta{Title: primaryID(a.ExternalID), Total: 1})
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func exportPath(name string) string {
	slug := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(fold(name)), "-"), "-")
	if slug == "" {
		slug = "tout"
	}
	if len(slug) > 40 {
		slug = strings.TrimRight(slug[:40], "-")
	}
	return filepath.Join(ExportDir(), "vulnkb-"+slug+"-"+time.Now().Format("20060102-1504")+".html")
}

// fold retire les accents courants (noms de fichiers).
func fold(s string) string {
	return strings.NewReplacer("é", "e", "è", "e", "ê", "e", "à", "a", "ç", "c", "ô", "o", "î", "i", "û", "u").Replace(s)
}

func writeExport(st *store.Store, path string, advs []model.Advisory, meta reportMeta) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return renderReport(f, st, advs, meta)
}

type reportMeta struct {
	Title, Query, Sort string
	Total              int
}

type reportCard struct {
	Anchor, ID, Aliases, Title, Source, SevClass, SevLabel string
	Exploited, HasExploit                                  bool
	EPSS, EPSSPct                                          string
	EPSSHigh                                               bool
	Action                                                 []template.HTML
	FixLink                                                string
	Fields                                                 [][2]string
	CVSS                                                   string
	Summary                                                template.HTML
	Exploits                                               []reportLink
	CertFR                                                 []reportLink
	Refs                                                   []string
}

type reportLink struct{ Label, Title, URL string }

type reportData struct {
	reportMeta
	Generated                   string
	Count                       int
	Sev                         [5]int
	NExploited, NExploit, NEPSS int
	Cards                       []reportCard
	Accent                      string
}

var sevClass = [...]string{"unk", "low", "med", "high", "crit"}

func renderReport(w io.Writer, st *store.Store, advs []model.Advisory, meta reportMeta) error {
	certfr, _ := st.CVEIndex("certfr")
	d := reportData{reportMeta: meta, Generated: time.Now().Format("2006-01-02 15:04"), Count: len(advs), Accent: pal.accent}
	for i, a := range advs {
		c := buildCard(st, a, certfr, i)
		lvl := effectiveSeverity(a).level
		d.Sev[lvl]++
		if a.Exploited {
			d.NExploited++
		}
		if a.HasExploit {
			d.NExploit++
		}
		if a.EPSS >= 0.1 {
			d.NEPSS++
		}
		d.Cards = append(d.Cards, c)
	}
	return reportTmpl.Execute(w, d)
}

func buildCard(st *store.Store, a model.Advisory, certfr map[string][]store.Ref, i int) reportCard {
	sev := effectiveSeverity(a)
	id := primaryID(a.ExternalID)
	c := reportCard{
		Anchor:     fmt.Sprintf("f%d", i+1),
		ID:         id,
		Title:      oneLine(a.Title),
		Source:     sourceOf(a.Source).name,
		SevClass:   sevClass[sev.level],
		SevLabel:   sev.label(),
		Exploited:  a.Exploited,
		HasExploit: a.HasExploit,
	}
	if rest := strings.TrimPrefix(a.ExternalID, id); strings.TrimSpace(rest) != "" {
		c.Aliases = strings.Trim(strings.TrimSpace(rest), "()")
	}
	if a.EPSS > 0 {
		c.EPSS, c.EPSSPct, c.EPSSHigh = fmtPct(a.EPSS), fmtPctile(a.EPSSPercentile), a.EPSS >= 0.1
	}

	// « Que faire »
	switch {
	case a.Exploited:
		c.Action = append(c.Action, `<span class="crit">⚠ Exploitée activement — à corriger en priorité</span>`)
	case a.HasExploit:
		c.Action = append(c.Action, `<span class="warn">⚑ Exploit public disponible — à traiter en priorité</span>`)
	case a.EPSS >= 0.1:
		c.Action = append(c.Action, template.HTML(`<span class="warn">⚑ Forte probabilité d'exploitation (EPSS `+html.EscapeString(fmtPct(a.EPSS))+`)</span>`))
	}
	switch rem := oneLine(shortRemediation(a.Remediation)); {
	case a.FixedVersions != "":
		c.Action = append(c.Action, template.HTML(`<span class="ok">↑ Mettre à jour : `+html.EscapeString(a.FixedVersions)+`</span>`))
	case rem != "":
		c.Action = append(c.Action, template.HTML("→ "+html.EscapeString(rem)))
	default:
		c.Action = append(c.Action, `<span class="muted">Pas de correctif indiqué — voir les références.</span>`)
	}
	c.FixLink = fixLink(a.References)

	add := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			c.Fields = append(c.Fields, [2]string{k, v})
		}
	}
	add("Composant", a.Component)
	typ := a.VulnType
	if typ == "" {
		typ = a.NVD.CWE
	}
	add("Type", describeCWEs(typ))
	add("Versions affectées", a.AffectedVersions)
	add("Corrigé dans", a.FixedVersions)
	if !a.Published.IsZero() {
		add("Publié", a.Published.Format("2006-01-02"))
	}
	if a.NVD.CVE != "" {
		c.CVSS = fmt.Sprintf("%.1f · CVSS %s · %s", a.NVD.Score, a.NVD.Version, a.NVD.CVE)
		if a.NVD.Vector != "" {
			c.CVSS += " · " + a.NVD.Vector
		}
	}
	c.Summary = markdownHTML(a.Summary)

	cves := store.CVEs(a.ExternalID)
	if ex, _ := st.ExploitsFor(cves); len(ex) > 0 {
		for _, e := range ex {
			c.Exploits = append(c.Exploits, reportLink{exploitKinds[e.Kind], e.Title, safeURL(e.URL)})
		}
	}
	if a.Source != "certfr" {
		seen := map[string]bool{}
		for _, cve := range cves {
			for _, r := range certfr[cve] {
				if !seen[r.ID] {
					seen[r.ID] = true
					c.CertFR = append(c.CertFR, reportLink{r.ID, r.Title, safeURL(r.URL)})
				}
			}
		}
	}
	for _, r := range a.References {
		if u := safeURL(r); u != "" {
			c.Refs = append(c.Refs, u)
		}
	}
	return c
}

// safeURL ne garde que les liens http(s).
func safeURL(u string) string {
	u = strings.TrimSpace(u)
	if strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://") {
		return u
	}
	return ""
}

var (
	mdFenceRe   = regexp.MustCompile("^\\s*(```|~~~)")
	mdHeadRe    = regexp.MustCompile(`^#{1,6}\s+(.+?)\s*#*$`)
	mdBulletRe  = regexp.MustCompile(`^\s*[-*+]\s+(.*)$`)
	mdCodeRe    = regexp.MustCompile("`([^`]+)`")
	mdLinkRe    = regexp.MustCompile(`!?\[([^\[\]\n]*)\]\((https?://[^)\s]+)\)`)
	mdBoldRe    = regexp.MustCompile(`\*\*(.+?)\*\*`)
	mdBareURLRe = regexp.MustCompile(`https?://[^\s<>"]+[^\s<>".,;:!?)\]]`)
)

// markdownHTML convertit le résumé (Markdown simple) en HTML sûr : tout le
// texte est échappé, seuls les liens http(s) deviennent des balises <a>.
func markdownHTML(src string) template.HTML {
	var b strings.Builder
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	var para, list []string
	flush := func() {
		if len(para) > 0 {
			b.WriteString("<p>" + mdInline(strings.Join(para, " ")) + "</p>\n")
			para = nil
		}
		if len(list) > 0 {
			b.WriteString("<ul>")
			for _, it := range list {
				b.WriteString("<li>" + mdInline(it) + "</li>")
			}
			b.WriteString("</ul>\n")
			list = nil
		}
	}
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		switch {
		case mdFenceRe.MatchString(l):
			flush()
			var code []string
			for i++; i < len(lines) && !mdFenceRe.MatchString(lines[i]); i++ {
				code = append(code, lines[i])
			}
			b.WriteString("<pre><code>" + html.EscapeString(strings.Join(code, "\n")) + "</code></pre>\n")
		case strings.TrimSpace(l) == "":
			flush()
		case mdHeadRe.MatchString(strings.TrimSpace(l)):
			flush()
			b.WriteString("<h4>" + mdInline(mdHeadRe.FindStringSubmatch(strings.TrimSpace(l))[1]) + "</h4>\n")
		case mdBulletRe.MatchString(l):
			if len(para) > 0 {
				b.WriteString("<p>" + mdInline(strings.Join(para, " ")) + "</p>\n")
				para = nil
			}
			list = append(list, mdBulletRe.FindStringSubmatch(l)[1])
		default:
			if len(list) > 0 {
				flush()
			}
			para = append(para, strings.TrimSpace(l))
		}
	}
	flush()
	return template.HTML(b.String())
}

// mdInline traite le code en ligne, les liens et le gras d'une ligne, après
// échappement complet du texte.
func mdInline(s string) string {
	s = html.EscapeString(s)
	var keep []string
	hold := func(v string) string {
		keep = append(keep, v)
		return fmt.Sprintf("\x00%d\x00", len(keep)-1)
	}
	s = mdCodeRe.ReplaceAllStringFunc(s, func(m string) string {
		return hold("<code>" + mdCodeRe.FindStringSubmatch(m)[1] + "</code>")
	})
	s = mdLinkRe.ReplaceAllStringFunc(s, func(m string) string {
		p := mdLinkRe.FindStringSubmatch(m)
		return hold(`<a href="` + p[2] + `">` + p[1] + `</a>`)
	})
	s = mdBareURLRe.ReplaceAllStringFunc(s, func(u string) string {
		return hold(`<a href="` + u + `">` + u + `</a>`)
	})
	s = mdBoldRe.ReplaceAllString(s, "<strong>$1</strong>")
	for i, v := range keep {
		s = strings.Replace(s, fmt.Sprintf("\x00%d\x00", i), v, 1)
	}
	return s
}

var reportTmpl = template.Must(template.New("rapport").Funcs(template.FuncMap{
	"fmtInt": fmtInt,
}).Parse(`<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vulnkb — {{.Title}}</title>
<style>
:root { --bg:#0d1117; --panel:#161b22; --border:#30363d; --text:#c9d1d9; --bright:#e6edf3; --muted:#8b949e;
  --accent:{{.Accent}}; --crit:#f85149; --high:#f0883e; --med:#d29922; --low:#8b949e; --ok:#3fb950; --purple:#bc8cff; }
@media (prefers-color-scheme: light) { :root { --bg:#ffffff; --panel:#f6f8fa; --border:#d0d7de; --text:#1f2328;
  --bright:#0d1117; --muted:#59636e; --crit:#cf222e; --high:#bc4c00; --med:#9a6700; --low:#59636e; --ok:#1a7f37; --purple:#8250df; } }
@media print { :root { --bg:#fff; --panel:#fff; --text:#000; --bright:#000; --muted:#444; } .card { break-inside: avoid; } nav { display:none; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 980px; margin: 0 auto; padding: 32px 20px 60px; }
header .brand { display:inline-block; background:var(--accent); color:#0d1117; font-weight:700; padding:2px 10px; border-radius:5px; font-family:ui-monospace, monospace; }
h1 { color:var(--bright); font-size:1.6rem; margin:.6rem 0 .2rem; }
.meta { color:var(--muted); font-size:.9rem; }
.stats { display:flex; flex-wrap:wrap; gap:10px; margin:18px 0 26px; }
.stat { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:8px 14px; }
.stat b { display:block; font-size:1.25rem; color:var(--bright); }
.stat span { color:var(--muted); font-size:.82rem; }
nav table { width:100%; border-collapse:collapse; font-size:.9rem; margin-bottom:30px; }
nav td, nav th { text-align:left; padding:5px 8px; border-bottom:1px solid var(--border); }
nav th { color:var(--muted); font-weight:500; }
nav td:nth-child(-n+3) { white-space:nowrap; } nav td:nth-child(1) { font-family:ui-monospace, monospace; font-size:.85rem; }
a { color:var(--accent); overflow-wrap:anywhere; }
.card { background:var(--panel); border:1px solid var(--border); border-left:4px solid var(--border); border-radius:10px; padding:18px 22px; margin:0 0 22px; }
.card.crit { border-left-color:var(--crit); } .card.high { border-left-color:var(--high); } .card.med { border-left-color:var(--med); }
.card h2 { color:var(--bright); font-size:1.15rem; margin:.3rem 0 .6rem; }
.id { font-family:ui-monospace, monospace; color:var(--accent); font-weight:600; }
.aliases { color:var(--muted); font-size:.85rem; font-family:ui-monospace, monospace; }
.badge { display:inline-block; font-size:.72rem; font-weight:700; padding:2px 8px; border-radius:4px; margin-right:6px; letter-spacing:.3px; }
.b-crit { color:var(--crit); background:color-mix(in srgb, var(--crit) 16%, transparent); }
.b-high { color:var(--high); background:color-mix(in srgb, var(--high) 16%, transparent); }
.b-med { color:var(--med); background:color-mix(in srgb, var(--med) 16%, transparent); }
.b-low, .b-unk { color:var(--low); background:color-mix(in srgb, var(--low) 16%, transparent); }
.b-kev { color:var(--crit); border:1px solid var(--crit); }
.b-exp { color:var(--purple); border:1px solid var(--purple); }
.b-epss { color:var(--high); border:1px solid var(--high); }
.todo { background:color-mix(in srgb, var(--accent) 8%, transparent); border-radius:8px; padding:10px 14px; margin:12px 0; }
.todo h3 { margin:0 0 4px; font-size:.95rem; color:var(--accent); }
.todo p { margin:2px 0; }
.crit { color:var(--crit); font-weight:600; } .warn { color:var(--high); font-weight:600; } .ok { color:var(--ok); font-weight:600; } .muted { color:var(--muted); }
dl { display:grid; grid-template-columns: 170px 1fr; gap:4px 14px; margin:12px 0; font-size:.92rem; }
dt { color:var(--accent); } dd { margin:0; overflow-wrap:anywhere; }
.summary { border-top:1px dashed var(--border); margin-top:12px; padding-top:8px; }
.summary h4 { color:var(--bright); margin:12px 0 4px; }
pre { background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:10px 12px; overflow-x:auto; font-size:.85rem; }
code { font-family:ui-monospace, "JetBrains Mono", monospace; font-size:.88em; }
.links h3 { font-size:.95rem; color:var(--accent); margin:14px 0 4px; }
.links ul { margin:0; padding-left:20px; font-size:.9rem; }
footer { color:var(--muted); font-size:.82rem; margin-top:40px; text-align:center; }
</style>
</head>
<body><main>
<header>
<span class="brand">vulnkb</span>
<h1>{{.Title}}</h1>
<div class="meta">Rapport généré le {{.Generated}}{{if .Sort}} · tri : {{.Sort}}{{end}}
{{- if gt .Total .Count}} · {{fmtInt .Count}} fiches exportées sur {{fmtInt .Total}} résultats{{else}} · {{fmtInt .Count}} fiche{{if gt .Count 1}}s{{end}}{{end}}</div>
</header>

{{if gt .Count 1}}
<section class="stats">
<div class="stat"><b class="crit">{{index .Sev 4}}</b><span>critiques</span></div>
<div class="stat"><b class="warn">{{index .Sev 3}}</b><span>élevées</span></div>
<div class="stat"><b>{{index .Sev 2}}</b><span>moyennes</span></div>
<div class="stat"><b>{{index .Sev 1}}</b><span>faibles</span></div>
<div class="stat"><b class="crit">{{.NExploited}}</b><span>exploitées activement</span></div>
<div class="stat"><b>{{.NExploit}}</b><span>avec exploit public</span></div>
<div class="stat"><b>{{.NEPSS}}</b><span>EPSS ≥ 10 %</span></div>
</section>
<nav><table>
<tr><th>Identifiant</th><th>Sévérité</th><th>EPSS</th><th>Titre</th></tr>
{{range .Cards}}<tr><td><a href="#{{.Anchor}}">{{.ID}}</a></td><td><span class="badge b-{{.SevClass}}">{{.SevLabel}}</span>{{if .Exploited}}<span class="badge b-kev">KEV</span>{{end}}</td><td>{{.EPSS}}</td><td>{{.Title}}</td></tr>
{{end}}</table></nav>
{{end}}

{{range .Cards}}
<article class="card {{.SevClass}}" id="{{.Anchor}}">
<div><span class="id">{{.ID}}</span> <span class="aliases">{{.Aliases}}</span></div>
<h2>{{.Title}}</h2>
<div>
<span class="badge b-{{.SevClass}}">{{.SevLabel}}</span>
{{if .Exploited}}<span class="badge b-kev">EXPLOITÉE (KEV)</span>{{end}}
{{if .HasExploit}}<span class="badge b-exp">EXPLOIT PUBLIC</span>{{end}}
{{if .EPSSHigh}}<span class="badge b-epss">EPSS {{.EPSS}}</span>{{end}}
<span class="muted">{{.Source}}</span>
</div>
<div class="todo"><h3>Que faire</h3>
{{range .Action}}<p>{{.}}</p>{{end}}
{{if .FixLink}}<p class="muted">↳ correctif / avis : <a href="{{.FixLink}}">{{.FixLink}}</a></p>{{end}}
</div>
<dl>
{{range .Fields}}<dt>{{index . 0}}</dt><dd>{{index . 1}}</dd>{{end}}
{{if .CVSS}}<dt>CVSS (NVD)</dt><dd>{{.CVSS}}</dd>{{end}}
{{if .EPSS}}<dt>EPSS</dt><dd>{{.EPSS}} de probabilité d'exploitation sous 30 jours · plus menaçant que {{.EPSSPct}} des CVE</dd>{{end}}
</dl>
{{if .Summary}}<div class="summary">{{.Summary}}</div>{{end}}
<div class="links">
{{if .Exploits}}<h3>Exploits publics</h3><ul>{{range .Exploits}}<li><b>{{.Label}}</b> — {{if .URL}}<a href="{{.URL}}">{{.Title}}</a>{{else}}{{.Title}}{{end}}</li>{{end}}</ul>{{end}}
{{if .CertFR}}<h3>Avis CERT-FR</h3><ul>{{range .CertFR}}<li>{{if .URL}}<a href="{{.URL}}">{{.Label}}</a>{{else}}{{.Label}}{{end}} — {{.Title}}</li>{{end}}</ul>{{end}}
{{if .Refs}}<h3>Références</h3><ul>{{range .Refs}}<li><a href="{{.}}">{{.}}</a></li>{{end}}</ul>{{end}}
</div>
</article>
{{end}}
<footer>Généré par vulnkb · sources : CISA KEV, OSV.dev, CERT-FR, NVD, EPSS (FIRST), Exploit-DB, Metasploit, PoC-in-GitHub</footer>
</main></body></html>
`))
