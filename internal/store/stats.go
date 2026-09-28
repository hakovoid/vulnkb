package store

import (
	"database/sql"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Overview rassemble les chiffres de la vue statistiques, calculés sur les
// entrées visibles (hors doublons NVD masqués).
type Overview struct {
	Visible    int
	BySeverity [5]int      // index = niveau model.Sev*
	ByYear     []YearCount // années de publication, les plus récentes d'abord
	Exploited  int         // CVE au catalogue CISA KEV
	HasExploit int         // exploit ou PoC public
	EPSS10     int         // EPSS ≥ 10 %
	EPSS50     int         // EPSS ≥ 50 %
	Recent30   int         // publiées ces 30 derniers jours
	TopCWE     []CWECount  // faiblesses les plus fréquentes
}

// YearCount compte les entrées publiées une année donnée.
type YearCount struct {
	Year  string
	Count int
}

// CWECount compte les entrées d'une faiblesse CWE.
type CWECount struct {
	CWE   string
	Count int
}

// Overview calcule la vue d'ensemble de la base.
func (s *Store) Overview(years, topCWE int) (Overview, error) {
	var o Overview
	rows, err := s.db.Query(`SELECT eff_level, COUNT(*) FROM advisories WHERE shadowed = 0 GROUP BY eff_level`)
	if err != nil {
		return o, err
	}
	for rows.Next() {
		var lvl, n int
		if err := rows.Scan(&lvl, &n); err != nil {
			rows.Close()
			return o, err
		}
		if lvl >= 0 && lvl < len(o.BySeverity) {
			o.BySeverity[lvl] += n
		}
		o.Visible += n
	}
	rows.Close()

	rows, err = s.db.Query(`SELECT strftime('%Y', published, 'unixepoch') y, COUNT(*) FROM advisories
WHERE shadowed = 0 AND published > 0 GROUP BY y ORDER BY y DESC LIMIT ?`, years)
	if err != nil {
		return o, err
	}
	for rows.Next() {
		var yc YearCount
		if err := rows.Scan(&yc.Year, &yc.Count); err != nil {
			rows.Close()
			return o, err
		}
		o.ByYear = append(o.ByYear, yc)
	}
	rows.Close()

	since := time.Now().AddDate(0, 0, -30).Unix()
	err = s.db.QueryRow(`SELECT IFNULL(SUM(exploited),0), IFNULL(SUM(has_exploit),0),
       IFNULL(SUM(epss >= 0.1),0), IFNULL(SUM(epss >= 0.5),0), IFNULL(SUM(published >= ?),0)
FROM advisories WHERE shadowed = 0`, since).Scan(&o.Exploited, &o.HasExploit, &o.EPSS10, &o.EPSS50, &o.Recent30)
	if err != nil {
		return o, err
	}

	o.TopCWE, err = s.topCWE(topCWE)
	return o, err
}

// topCWE compte les faiblesses citées par les entrées visibles.
func (s *Store) topCWE(n int) ([]CWECount, error) {
	rows, err := s.db.Query(`SELECT vuln_type FROM advisories WHERE shadowed = 0 AND vuln_type LIKE '%CWE-%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		for _, part := range strings.Split(v, ",") {
			if c := strings.TrimSpace(part); strings.HasPrefix(c, "CWE-") {
				counts[c]++
			}
		}
	}
	out := make([]CWECount, 0, len(counts))
	for c, k := range counts {
		out = append(out, CWECount{c, k})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].CWE < out[j].CWE
	})
	if len(out) > n {
		out = out[:n]
	}
	return out, rows.Err()
}

// CountWithWatch compte les résultats de query pour une liste de
// surveillance donnée (au lieu de la liste courante) : sert à mesurer
// l'exposition produit par produit.
func (s *Store) CountWithWatch(terms []string, query string) (int, error) {
	q := ParseQuery(query)
	q.WatchReq, q.Watch = true, terms
	if q.Impossible() {
		return 0, nil
	}
	from, _, args := searchFrom(q)
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) `+from, args...).Scan(&n)
	return n, err
}

// TermExposure compte, pour un terme de la liste de surveillance, les
// fiches élevées ou critiques qui le concernent, dont exploitées.
type TermExposure struct {
	Term              string
	Severe, Exploited int
}

var nonAlnum = regexp.MustCompile(`[^\p{L}\p{N}]+`)

// words réduit un texte à ses mots en minuscules, séparés par une espace et
// encadrés d'espaces (même découpage que l'index plein-texte).
func words(s string) string {
	return " " + strings.TrimSpace(nonAlnum.ReplaceAllString(strings.ToLower(s), " ")) + " "
}

// termMatches reproduit en mémoire la règle du filtre « mes » pour un terme.
// La version d'un terme qualifié n'est pas vérifiée ici (voir affects).
func termMatches(term, externalID, title, component string) bool {
	wt := ParseWatchTerm(term)
	if wt.Ecosystem != "" {
		comp := strings.ToLower(component)
		pkg := strings.ToLower(wt.Name)
		head := wt.Label + " "
		if !strings.HasPrefix(comp, head) {
			return false
		}
		for _, p := range strings.Split(strings.TrimPrefix(comp, head), ", ") {
			if p == pkg {
				return true
			}
		}
		return false
	}
	// terme simple : suite de mots, le dernier en début de mot
	t := strings.TrimSpace(words(wt.Name))
	return t != "" && strings.Contains(words(externalID)+words(title)+words(component), " "+t)
}

// affects dit si l'entrée id touche l'une des versions du terme, avec la
// même prudence que le filtre : sans plage connue pour le paquet, oui.
func (s *Store) affects(id string, t WatchTerm) (bool, error) {
	var known, hit bool
	err := s.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM advisory_ranges WHERE id = ? AND eco = ? AND pkg = ?),
       EXISTS (SELECT 1 FROM advisory_ranges WHERE id = ? AND eco = ? AND pkg = ? AND vk_affected(?, introduced, fixed, last_affected))`,
		id, t.Label, t.Package, id, t.Label, t.Package, t.Versions).Scan(&known, &hit)
	return !known || hit, err
}

// ExposureByTerm mesure l'exposition de chaque terme surveillé en une seule
// requête : les fiches élevées ou critiques de la liste sont lues, puis
// attribuées à chaque terme en mémoire. Résultat trié par exposition.
func (s *Store) ExposureByTerm(terms []string) ([]TermExposure, error) {
	q := ParseQuery("sev:high+")
	q.WatchReq, q.Watch = true, terms
	if q.Impossible() {
		return nil, nil
	}
	from, _, args := searchFrom(q)
	rows, err := s.db.Query(`SELECT a.id, a.external_id, a.title, a.component, a.exploited `+from, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type row struct {
		id, ext, title, comp string
		exploited            bool
	}
	var all []row
	for rows.Next() {
		var r row
		var ext, title, comp sql.NullString
		if err := rows.Scan(&r.id, &ext, &title, &comp, &r.exploited); err != nil {
			return nil, err
		}
		r.ext, r.title, r.comp = ext.String, title.String, comp.String
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close() // avant les requêtes de affects
	var out []TermExposure
	for _, t := range terms {
		e := TermExposure{Term: t}
		wt := ParseWatchTerm(t)
		for _, r := range all {
			if !termMatches(t, r.ext, r.title, r.comp) {
				continue
			}
			if wt.Versions != "" {
				if ok, err := s.affects(r.id, wt); err != nil {
					return nil, err
				} else if !ok {
					continue
				}
			}
			e.Severe++
			if r.exploited {
				e.Exploited++
			}
		}
		if e.Severe > 0 {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severe != out[j].Severe {
			return out[i].Severe > out[j].Severe
		}
		return out[i].Term < out[j].Term
	})
	return out, nil
}
