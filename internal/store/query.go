package store

import (
	"slices"
	"sort"
	"strconv"
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
//	exploit             un exploit public existe
//	epss:10             probabilité d'exploitation EPSS d'au moins 10 %
//	mes                 produits de la liste de surveillance
type Query struct {
	Text       string
	Severities []int    // niveaux model.Sev*
	Sources    []string // valeurs de la colonne source
	Exploited  bool
	Exploit    bool     // filtre « exploit » : exploit public disponible
	EPSSMin    float64  // filtre « epss:N » : probabilité EPSS ≥ N % (0 = pas de filtre)
	Watch      []string // termes de la liste de surveillance (filtre « mes »)
	WatchReq   bool     // « mes » demandé (même si la liste est vide)
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
		case !hasColon && (k == "exploit" || k == "exploits" || k == "poc"):
			q.Exploit = true
		case hasColon && k == "epss":
			v := strings.TrimRight(strings.TrimSpace(val), "+%")
			f, err := strconv.ParseFloat(strings.Replace(v, ",", ".", 1), 64)
			if err != nil || f <= 0 || f > 100 {
				q.Invalid = append(q.Invalid, tok)
				continue
			}
			q.EPSSMin = f / 100
		case !hasColon && (k == "mes" || k == "watch" || k == "surveille" || k == "surveilles"):
			q.WatchReq = true
			q.Watch = Watchlist()
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
	return len(q.Severities) > 0 || len(q.Sources) > 0 || q.Exploited || q.Exploit || q.WatchReq || q.EPSSMin > 0
}

// Impossible est vrai quand la requête ne peut renvoyer aucun résultat :
// « mes » demandé alors que la liste de surveillance est vide.
func (q Query) Impossible() bool {
	return q.WatchReq && len(q.Watch) == 0
}

// matchExpr est la requête plein-texte du texte libre (vide s'il n'y en a
// pas). Le filtre « mes » est traité à part, dans where().
func (q Query) matchExpr() string {
	return ftsQuery(q.Text)
}

// watchEcosystems associe le préfixe d'un terme qualifié (« npm:express ») au
// mot qui désigne l'écosystème dans l'index, et à son nom dans le composant
// des fiches OSV (« PyPI fastapi », « crates.io serde »…).
var watchEcosystems = map[string]struct{ token, label string }{
	"npm": {"npm", "npm"}, "pypi": {"pypi", "pypi"}, "go": {"go", "go"},
	"packagist": {"packagist", "packagist"}, "crates": {"crates", "crates.io"},
	"maven": {"maven", "maven"}, "nuget": {"nuget", "nuget"}, "rubygems": {"rubygems", "rubygems"},
}

// watchClause construit la condition SQL du filtre « mes » (sur l'alias a),
// en deux temps pour rester rapide :
//  1. une seule recherche dans l'index plein-texte ramène les candidats de
//     tous les termes (a.rowid IN …) ;
//  2. chaque candidat est gardé s'il correspond à un terme simple (« nginx »,
//     en début de mot dans l'identifiant, le titre ou le composant), ou si
//     un paquet qualifié (« npm:react ») figure exactement dans la liste du
//     composant (« npm react, react-dom ») — ce qui écarte
//     « @aws-amplify/codegen-ui-react » et les faux positifs des noms courts ;
//     avec une version (« npm:react@18.2.0 »), seulement si l'entrée la
//     touche (voir versionCond).
func watchClause(terms []string) (string, []any) {
	const inFTS = "a.rowid IN (SELECT rowid FROM advisories_fts WHERE advisories_fts MATCH ?)"
	var candidates, plain, conds []string
	var args []any
	for _, raw := range terms {
		t := ParseWatchTerm(raw)
		if t.Name == "" {
			continue
		}
		if t.Ecosystem != "" {
			e := watchEcosystems[t.Ecosystem]
			pkg := strings.ToLower(t.Name)
			p := likeEscape(pkg)
			candidates = append(candidates, `component:(`+e.token+` "`+t.Name+`")`)
			cond := `(lower(a.component) = ? OR lower(a.component) LIKE ? ESCAPE '\'
     OR lower(a.component) LIKE ? ESCAPE '\' OR lower(a.component) LIKE ? ESCAPE '\')`
			args = append(args, e.label+" "+pkg, likeEscape(e.label)+" "+p+",%", "%, "+p, "%, "+p+",%")
			// version connue : seulement les entrées qui la touchent
			if t.Versions != "" {
				vc, vargs := versionCond(t)
				cond = "(" + cond + " AND " + vc + ")"
				args = append(args, vargs...)
			}
			conds = append(conds, cond)
			continue
		}
		plain = append(plain, `"`+t.Name+`"*`)
	}
	if len(plain) > 0 {
		expr := "{external_id title component}:(" + strings.Join(plain, " OR ") + ")"
		candidates = append(candidates, expr)
		conds = append([]string{inFTS}, conds...)
		args = append([]any{expr}, args...)
	}
	if len(candidates) == 0 {
		return "", nil
	}
	clause := " AND " + inFTS + " AND (" + strings.Join(conds, "\n  OR ") + ")"
	return clause, append([]any{"(" + strings.Join(candidates, " OR ") + ")"}, args...)
}

// likeEscape neutralise les jokers de LIKE (%, _) d'un nom de paquet.
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(s)
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
	if q.Exploit {
		sb.WriteString(" AND a.has_exploit = 1") // tenu à jour par RefreshHasExploit
	}
	if q.EPSSMin > 0 {
		sb.WriteString(" AND a.epss >= ?")
		args = append(args, q.EPSSMin)
	}
	if len(q.Watch) > 0 {
		clause, wargs := watchClause(q.Watch)
		sb.WriteString(clause)
		args = append(args, wargs...)
	}
	return sb.String(), args
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
