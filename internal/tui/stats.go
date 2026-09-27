package tui

import (
	"fmt"
	"strings"

	"vulnkb/internal/store"
)

// barWidth est la longueur maximale d'une barre d'histogramme.
const barWidth = 34

// bar dessine une barre proportionnelle à v/max, avec des huitièmes de bloc.
func bar(v, max int, color string) string {
	if max <= 0 || v <= 0 {
		return ""
	}
	eighths := v * barWidth * 8 / max
	if eighths == 0 {
		eighths = 1
	}
	parts := []string{"", "▏", "▎", "▍", "▌", "▋", "▊", "▉"}
	return color + strings.Repeat("█", eighths/8) + parts[eighths%8] + reset
}

func maxOf(vals ...int) int {
	m := 0
	for _, v := range vals {
		m = max(m, v)
	}
	return m
}

// statRow aligne libellé, barre et valeur.
func statRow(label string, v, max int, color string) string {
	b := bar(v, max, color)
	pad := barWidth + 1 - visibleLen(b)
	return fmt.Sprintf("  %-22s %s%s %s", truncEllipsis(label, 22), b, strings.Repeat(" ", max0(pad)), fmtInt(v))
}

func max0(n int) int { return max(0, n) }

// StatsReport décrit la base et ton exposition : sévérités, années, sources,
// failles exploitées, CWE fréquentes, et le détail de la liste « mes ».
// Partagé par la fenêtre Alt-I et la commande « vulnkb stats ».
func StatsReport(st *store.Store) []string {
	o, err := st.Overview(10, 10)
	if err != nil {
		return []string{red + "statistiques indisponibles : " + err.Error() + reset}
	}
	sevColors := [...]string{gray, gray, yellow, orange, red}
	sevNames := [...]string{"inconnue", "faible", "moyenne", "élevée", "critique"}
	var l []string
	h := func(title string) { l = append(l, "", bold+title+reset, "") }

	l = append(l, bold+"Vue d'ensemble"+reset, "",
		fmt.Sprintf("  %s entrées visibles · %s publiées ces 30 derniers jours", fmtInt(o.Visible), fmtInt(o.Recent30)))

	h("Par sévérité")
	m := maxOf(o.BySeverity[:]...)
	for lvl := 4; lvl >= 0; lvl-- {
		l = append(l, statRow(sevNames[lvl], o.BySeverity[lvl], m, sevColors[lvl]))
	}

	h("Menace")
	m = maxOf(o.HasExploit, o.EPSS10, o.Exploited, o.EPSS50)
	l = append(l,
		statRow("exploitées (KEV)", o.Exploited, m, red),
		statRow("avec exploit public", o.HasExploit, m, magenta),
		statRow("EPSS ≥ 10 %", o.EPSS10, m, orange),
		statRow("EPSS ≥ 50 %", o.EPSS50, m, red))

	h("Par année de publication")
	m = 0
	for _, y := range o.ByYear {
		m = max(m, y.Count)
	}
	for _, y := range o.ByYear {
		l = append(l, statRow(y.Year, y.Count, m, labelColor))
	}

	if stats, _ := st.SourceStats(); len(stats) > 0 {
		h("Par source")
		m = 0
		for _, s := range stats {
			m = max(m, s.Count)
		}
		for _, s := range stats {
			info := sourceOf(s.Source)
			l = append(l, statRow(info.name, s.Count, m, info.color))
		}
	}

	if len(o.TopCWE) > 0 {
		h("Faiblesses les plus fréquentes (CWE)")
		m = o.TopCWE[0].Count
		for _, c := range o.TopCWE {
			name := c.CWE
			if n, ok := cweNames[c.CWE]; ok {
				name += " " + n
			}
			l = append(l, statRow(name, c.Count, m, labelColor))
		}
	}

	return append(l, exposureReport(st)...)
}

// exposureReport détaille la liste de surveillance : totaux, puis les
// produits les plus exposés.
func exposureReport(st *store.Store) []string {
	terms := store.Watchlist()
	l := []string{"", bold + "Ton exposition (liste « mes »)" + reset, ""}
	if len(terms) == 0 {
		return append(l, "  liste vide — vulnkb watch add nginx, ou vulnkb watch import ~/projets")
	}
	count := func(q string) int { n, _ := st.CountMatches(q); return n }
	total := count("mes")
	crit, high := count("mes sev:crit"), count("mes sev:high")
	expl, exp, epss := count("mes exploitee"), count("mes exploit"), count("mes epss:10")
	l = append(l, fmt.Sprintf("  %s termes surveillés · %s fiches liées", fmtInt(len(terms)), fmtInt(total)), "")
	m := maxOf(crit, high, expl, exp, epss)
	l = append(l,
		statRow("critiques", crit, m, red),
		statRow("élevées", high, m, orange),
		statRow("exploitées (KEV)", expl, m, red),
		statRow("avec exploit public", exp, m, magenta),
		statRow("EPSS ≥ 10 %", epss, m, orange))

	prods, _ := st.ExposureByTerm(terms)
	if len(prods) > 12 {
		prods = prods[:12]
	}
	if len(prods) == 0 {
		return append(l, "", "  aucun produit surveillé n'a de faille élevée ou critique")
	}
	l = append(l, "", bold+"Produits les plus exposés"+reset+dim+" (fiches élevées ou critiques · dont exploitées)"+reset, "")
	m = prods[0].Severe
	for _, p := range prods {
		row := statRow(p.Term, p.Severe, m, orange)
		if p.Exploited > 0 {
			row += boldRed + fmt.Sprintf("  ● %d exploitée%s", p.Exploited, plural(p.Exploited)) + reset
		}
		l = append(l, row)
	}
	return append(l, "", dim+"Pour le détail : recherche « mes sev:high+ », ou exporte-la (Alt-R)."+reset)
}

func plural(n int) string {
	if n > 1 {
		return "s"
	}
	return ""
}
