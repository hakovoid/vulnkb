package store

import (
	"slices"
	"sort"
	"strings"

	"vulnkb/internal/model"
)

// Query est une saisie de recherche décomposée : texte libre (index
// plein-texte) et filtres sur des champs précis.
//
// Syntaxe des filtres, combinables avec le texte :
//
//	sev:crit            sévérité (crit, high, med, low, inconnue) ; plusieurs
//	sev:crit,high       valeurs séparées par des virgules ; « high+ » = élevée
//	sev:high+           ou plus
//	src:kev             source (kev, osv, fr, ia) ; plusieurs valeurs possibles
//	exploitee           failles exploitées activement (CVE présent dans CISA KEV)
type Query struct {
	Text       string
	Severities []int    // niveaux model.Sev*
	Sources    []string // valeurs de la colonne source
	Exploited  bool
	Invalid    []string // filtres non reconnus
}

var sevNames = map[string][]int{
	"crit": {model.SevCritical}, "critical": {model.SevCritical}, "critique": {model.SevCritical},
	"high": {model.SevHigh}, "haute": {model.SevHigh}, "elevee": {model.SevHigh},
	"med": {model.SevMedium}, "medium": {model.SevMedium}, "moderate": {model.SevMedium}, "moy": {model.SevMedium}, "moyenne": {model.SevMedium},
	"low": {model.SevLow}, "faible": {model.SevLow},
	"inconnue": {model.SevUnknown}, "unknown": {model.SevUnknown}, "aucune": {model.SevUnknown},
}

var srcNames = map[string]string{
	"kev": "cisa-kev", "cisa": "cisa-kev", "cisa-kev": "cisa-kev",
	"osv": "osv",
	"fr":  "certfr", "certfr": "certfr", "cert-fr": "certfr",
	"ia": "article-ia", "article": "article-ia", "article-ia": "article-ia",
	"nvd": "nvd",
}

// ParseQuery sépare le texte libre des filtres.
func ParseQuery(raw string) Query {
	var q Query
	var text []string
	sevs := map[int]bool{}
	srcs := map[string]bool{}
	for _, tok := range strings.Fields(raw) {
		key, val, hasColon := strings.Cut(tok, ":")
		k := fold(key)
		switch {
		case !hasColon && (k == "exploitee" || k == "exploitees" || k == "exploited"):
			q.Exploited = true
		case hasColon && (k == "sev" || k == "severite"):
			ok := val != ""
			for _, v := range strings.Split(fold(val), ",") {
				orMore := strings.HasSuffix(v, "+")
				levels, known := sevNames[strings.TrimSuffix(v, "+")]
				if !known {
					ok = false
					continue
				}
				for _, l := range levels {
					sevs[l] = true
					for m := l + 1; orMore && m <= model.SevCritical; m++ {
						sevs[m] = true
					}
				}
			}
			if !ok {
				q.Invalid = append(q.Invalid, tok)
			}
		case hasColon && (k == "src" || k == "source"):
			ok := val != ""
			for _, v := range strings.Split(fold(val), ",") {
				if s, known := srcNames[v]; known {
					srcs[s] = true
				} else {
					ok = false
				}
			}
			if !ok {
				q.Invalid = append(q.Invalid, tok)
			}
		default:
			text = append(text, tok)
		}
	}
	q.Text = strings.Join(text, " ")
	for l := range sevs {
		q.Severities = append(q.Severities, l)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(q.Severities)))
	for s := range srcs {
		q.Sources = append(q.Sources, s)
	}
	sort.Strings(q.Sources)
	return q
}

// HasFilters indique si la requête restreint autre chose que le texte.
func (q Query) HasFilters() bool {
	return len(q.Severities) > 0 || len(q.Sources) > 0 || q.Exploited
}

// fold met en minuscules et retire les accents courants du français.
func fold(s string) string {
	return strings.NewReplacer("é", "e", "è", "e", "ê", "e", "É", "e", "à", "a", "ç", "c").Replace(strings.ToLower(s))
}

// where construit la clause de filtrage SQL (sur l'alias « a ») et ses
// arguments, à ajouter après une clause WHERE existante.
func (q Query) where() (string, []any) {
	var sb strings.Builder
	var args []any
	// les entrées NVD déjà couvertes par une autre source ne s'affichent que
	// si l'on demande explicitement src:nvd
	if !slices.Contains(q.Sources, "nvd") {
		sb.WriteString(" AND a.shadowed = 0")
	}
	if len(q.Severities) > 0 {
		sb.WriteString(" AND a.eff_level IN (" + placeholders(len(q.Severities)) + ")")
		for _, l := range q.Severities {
			args = append(args, l)
		}
	}
	if len(q.Sources) > 0 {
		sb.WriteString(" AND a.source IN (" + placeholders(len(q.Sources)) + ")")
		for _, s := range q.Sources {
			args = append(args, s)
		}
	}
	if q.Exploited {
		sb.WriteString(" AND a.exploited = 1") // tenu à jour par RefreshExploited
	}
	return sb.String(), args
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
