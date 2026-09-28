package tui

import (
	"fmt"
	"strings"
	"time"

	"vulnkb/internal/source"
	"vulnkb/internal/store"
)

// SourceReport décrit les sources de la base : ce qu'elles contiennent, leur
// nombre d'entrées, leur dernière collecte, les compléments (scores,
// exploits) et les noms à passer à « vulnkb sync ». Partagé par la fenêtre
// Alt-S et la commande « vulnkb sources ».
func SourceReport(st *store.Store) []string {
	stats, _ := st.SourceStats()
	now := time.Now()
	lines := []string{bold + "Sources en base" + reset, ""}
	if len(stats) == 0 {
		lines = append(lines, "  aucune entrée — lance « vulnkb sync »")
	}
	for _, s := range stats {
		info := sourceOf(s.Source)
		when := "jamais"
		if !s.Last.IsZero() {
			when = s.Last.Local().Format("2006-01-02 15:04") + dim + " (" + syncAge(s.Last, now) + ")" + reset
		}
		lines = append(lines, fmt.Sprintf("  %s  %-42s %9s   %s",
			info.color+info.badge+reset, truncEllipsis(info.name, 42), fmtInt(s.Count), when))
	}

	nvd, _ := st.CountNVD()
	expl, _ := st.CountExploits()
	lines = append(lines, "", bold+"Compléments"+reset, "",
		fmt.Sprintf("  %-47s %9s", "scores CVSS (NVD)", fmtInt(nvd)),
		fmt.Sprintf("  %-47s %9s", "exploits et PoC publics (références)", fmtInt(expl)))
	if n, _ := st.CountEPSS(); n > 0 {
		lines = append(lines, fmt.Sprintf("  %-47s %9s", "probabilités d'exploitation (EPSS)", fmtInt(n)))
	}
	if recs, ssvc, _ := st.CountCVEList(); recs+ssvc > 0 {
		lines = append(lines,
			fmt.Sprintf("  %-47s %9s", "CVE complétés par la liste officielle", fmtInt(recs)),
			fmt.Sprintf("  %-47s %9s", "évaluations SSVC de la CISA", fmtInt(ssvc)))
	}

	var names []string
	for _, s := range source.All() {
		n := s.Name()
		if source.IsOptional(s) {
			n += dim + " (à la demande)" + reset
		}
		names = append(names, n)
	}
	names = append(names, "nvd", "cvelist", "exploits", "epss")
	lines = append(lines, "", bold+"Noms pour « vulnkb sync <nom> »"+reset, "")
	lines = append(lines, wrapLines("  "+strings.Join(names, ", "), 96)...)
	lines = append(lines, "", dim+"Sans nom, « vulnkb sync » collecte tout sauf les sources à la demande."+reset)
	return lines
}
