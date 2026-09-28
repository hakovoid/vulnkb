// Package versions compare des numéros de version de paquets et dit si une
// version tombe dans une plage vulnérable (au sens d'OSV : introduite en X,
// corrigée en Y, ou dernière version touchée Z).
//
// La comparaison est tolérante et vaut pour les écosystèmes courants : semver
// (npm, Go, crates.io, Packagist), PEP 440 (PyPI : rc, post, dev, époque),
// préfixe « v ». Elle découpe la version en nombres et en mots : les nombres
// se comparent numériquement, les mots de pré-version (alpha, beta, rc, dev…)
// passent avant la version finale, et les mots de post-version (post, patch)
// après.
//
// Règle de prudence : une version illisible (empreinte git…) est considérée
// comme touchée. Manquer une faille est pire qu'un faux positif.
package versions

import (
	"strconv"
	"strings"
	"unicode"
)

// token est un morceau de version : un nombre ou un mot.
type token struct {
	num   int64
	word  string
	isNum bool
}

// preRank ordonne les mots de pré-version ; plus petit = plus ancien. Les
// mots inconnus se placent juste avant la version finale.
var preRank = map[string]int{
	"dev": 0, "snapshot": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2,
	"m": 3, "milestone": 3, "pre": 4, "preview": 4, "c": 5, "rc": 5, "cr": 5,
}

// postWords suivent la version finale (1.0.post1 > 1.0).
var postWords = map[string]bool{"post": true, "p": true, "patch": true, "pl": true, "sp": true, "r": true, "rev": true}

// neutral sont les mots qui valent la version finale (Maven : « 1.0.Final »).
var neutral = map[string]bool{"final": true, "ga": true, "release": true}

// parse découpe une version en jetons ; ok est faux si elle n'est pas
// lisible (vide, ou sans aucun chiffre).
func parse(v string) (epoch int64, toks []token, ok bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "=")
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 { // métadonnées de build semver
		v = v[:i]
	}
	if i := strings.IndexByte(v, '!'); i > 0 { // époque PEP 440
		if e, err := strconv.ParseInt(v[:i], 10, 64); err == nil {
			epoch, v = e, v[i+1:]
		}
	}
	if v == "" || !strings.ContainsAny(v, "0123456789") {
		return 0, nil, false
	}
	// une empreinte git (40 caractères hexadécimaux) n'est pas une version
	if len(v) >= 12 && strings.Trim(v, "0123456789abcdef") == "" {
		return 0, nil, false
	}
	var cur strings.Builder
	var curNum bool
	var prevSep rune
	inRelease := true // encore dans la partie numérique (1.2.3)
	flush := func() {
		if cur.Len() == 0 {
			return
		}
		s := cur.String()
		cur.Reset()
		if curNum {
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				n = 1<<62 - 1
			}
			toks = append(toks, token{num: n, isNum: true})
			return
		}
		if neutral[s] {
			return
		}
		toks = append(toks, token{word: s})
	}
	for _, r := range v {
		switch {
		case unicode.IsDigit(r):
			if cur.Len() > 0 && !curNum {
				flush()
			}
			// semver : « 5.0.0-0 », « 0.0.0-2021… » (pseudo-version Go) sont
			// des pré-versions
			if cur.Len() == 0 && prevSep == '-' && inRelease && len(toks) > 0 {
				toks = append(toks, token{word: "-"})
				inRelease = false
			}
			curNum = true
			cur.WriteRune(r)
		case unicode.IsLetter(r):
			if cur.Len() > 0 && curNum {
				flush()
			}
			curNum, inRelease = false, false
			cur.WriteRune(r)
		default: // séparateurs : . - _ ~
			flush()
		}
		if !unicode.IsDigit(r) && !unicode.IsLetter(r) {
			prevSep = r
		} else {
			prevSep = 0
		}
	}
	flush()
	return epoch, toks, true
}

// split sépare la partie numérique de tête (1.2.3), sans ses zéros finaux
// (1.2 == 1.2.0), du reste (rc1, post2…).
func split(toks []token) (release, rest []token) {
	i := 0
	for i < len(toks) && toks[i].isNum {
		i++
	}
	release, rest = toks[:i], toks[i:]
	for len(release) > 0 && release[len(release)-1].num == 0 {
		release = release[:len(release)-1]
	}
	return release, rest
}

// wordRank place un mot par rapport à la version finale (0) : négatif pour
// une pré-version, positif pour une post-version.
func wordRank(w string) int {
	if w == "-" { // pré-version semver sans nom : la plus ancienne
		return -11
	}
	if postWords[w] {
		return 1
	}
	if r, ok := preRank[w]; ok {
		return r - 10
	}
	return -1
}

// Compare renvoie -1, 0 ou 1 selon que a est plus ancienne, égale ou plus
// récente que b ; ok est faux si l'une des deux est illisible.
func Compare(a, b string) (c int, ok bool) {
	ea, ta, oka := parse(a)
	eb, tb, okb := parse(b)
	if !oka || !okb {
		return 0, false
	}
	if ea != eb {
		return sign(ea - eb), true
	}
	ra, ta := split(ta)
	rb, tb := split(tb)
	for i := 0; i < max(len(ra), len(rb)); i++ {
		var x, y int64
		if i < len(ra) {
			x = ra[i].num
		}
		if i < len(rb) {
			y = rb[i].num
		}
		if x != y {
			return sign(x - y), true
		}
	}
	for i := 0; ; i++ {
		switch {
		case i >= len(ta) && i >= len(tb):
			return 0, true
		case i >= len(ta): // a est finie : b est plus récente sauf pré-version
			return -tail(tb[i]), true
		case i >= len(tb):
			return tail(ta[i]), true
		}
		x, y := ta[i], tb[i]
		switch {
		case x.isNum && y.isNum:
			if x.num != y.num {
				return sign(x.num - y.num), true
			}
		case x.isNum: // 1.2.1 > 1.2.rc1 et > 1.2.post1
			return 1, true
		case y.isNum:
			return -1, true
		default:
			if rx, ry := wordRank(x.word), wordRank(y.word); rx != ry {
				return sign(int64(rx - ry)), true
			}
			if x.word != y.word {
				return strings.Compare(x.word, y.word), true
			}
		}
	}
}

// tail dit si une version prolongée par t est plus récente (1) ou plus
// ancienne (-1) que la version sans t : 1.0.1 et 1.0.post1 > 1.0 > 1.0rc1.
func tail(t token) int {
	if t.isNum || wordRank(t.word) > 0 {
		return 1
	}
	return -1
}

func sign(n int64) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// InRange dit si v est touchée par la plage [introduced, fixed[ ou
// [introduced, lastAffected]. introduced vide ou « 0 » : depuis toujours ;
// fixed et lastAffected vides : pas encore corrigée. Une borne illisible rend
// la réponse prudente (touchée).
func InRange(v, introduced, fixed, lastAffected string) bool {
	if introduced != "" && introduced != "0" {
		if c, ok := Compare(v, introduced); ok && c < 0 {
			return false
		}
	}
	if fixed != "" {
		if c, ok := Compare(v, fixed); ok && c >= 0 {
			return false
		}
	}
	if lastAffected != "" {
		if c, ok := Compare(v, lastAffected); ok && c > 0 {
			return false
		}
	}
	return true
}

// AnyInRange applique InRange à une liste de versions séparées par des
// virgules (le même paquet peut être utilisé en plusieurs versions).
func AnyInRange(list, introduced, fixed, lastAffected string) bool {
	for _, v := range strings.Split(list, ",") {
		if v = strings.TrimSpace(v); v != "" && InRange(v, introduced, fixed, lastAffected) {
			return true
		}
	}
	return false
}
