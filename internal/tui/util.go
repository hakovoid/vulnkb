package tui

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// Séquences ANSI de mise en forme, indépendantes du thème.
const (
	reset = "\x1b[0m"
	bold  = "\x1b[1m"
	dim   = "\x1b[2m"
)

// visibleLen est la largeur affichée d'une chaîne, codes ANSI exclus et
// caractères larges comptés double.
func visibleLen(s string) int { return ansi.StringWidth(s) }

// trunc coupe une chaîne à n colonnes visibles, en préservant les codes ANSI.
func trunc(s string, n int) string {
	if n <= 0 {
		return ""
	}
	return ansi.Truncate(s, n, "")
}

// truncEllipsis coupe à n colonnes en signalant la coupure par « … ».
func truncEllipsis(s string, n int) string {
	if n <= 0 {
		return ""
	}
	return ansi.Truncate(s, n, "…")
}

// wrapLines découpe un texte en lignes d'au plus w colonnes visibles, mot par
// mot ; un mot plus long que la ligne est coupé.
func wrapLines(s string, w int) []string {
	if w <= 0 {
		return []string{s}
	}
	var lines []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			lines = append(lines, "")
			continue
		}
		cur := ""
		curLen := 0
		for _, word := range words {
			wl := visibleLen(word)
			if curLen > 0 && curLen+1+wl > w {
				lines = append(lines, cur)
				cur, curLen = "", 0
			}
			for wl > w { // mot trop long (URL…) : coupé
				lines = append(lines, trunc(word, w))
				word = ansi.Cut(word, w, wl)
				wl = visibleLen(word)
			}
			if curLen > 0 {
				cur += " "
				curLen++
			}
			cur += word
			curLen += wl
		}
		if cur != "" {
			lines = append(lines, cur)
		}
	}
	return lines
}

// fmtInt groupe les milliers : 23456 -> « 23 456 ».
func fmtInt(n int) string {
	s := strconv.Itoa(n)
	var out []byte
	for i := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ' ')
		}
		out = append(out, s[i])
	}
	return string(out)
}

// humanBytes met en forme une taille : « 1,1 Go », « 168 Mo ».
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return strings.Replace(strconv.FormatFloat(float64(n)/(1<<30), 'f', 1, 64), ".", ",", 1) + " Go"
	case n >= 1<<20:
		return strconv.FormatInt(n/(1<<20), 10) + " Mo"
	case n >= 1<<10:
		return strconv.FormatInt(n/(1<<10), 10) + " Ko"
	default:
		return strconv.FormatInt(n, 10) + " o"
	}
}

func maxi(a, b int) int { return max(a, b) }

func minInt(a, b int) int { return min(a, b) }
