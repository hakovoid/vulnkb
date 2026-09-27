package tui

import (
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
)

// codeStyle est le thème de coloration ; VULNKB_CODE_STYLE permet d'en
// choisir un autre (ex. « github » pour un terminal clair).
var codeStyle = func() *chroma.Style {
	if s := os.Getenv("VULNKB_CODE_STYLE"); s != "" {
		return styles.Get(s)
	}
	return styles.Get("monokai")
}()

// codeFormatter produit les couleurs du code : 256 couleurs par défaut,
// 16 millions si le terminal les gère (voir initTheme).
var codeFormatter = formatters.TTY256

var (
	fenceOpenRe  = regexp.MustCompile("^\\s*(```|~~~)\\s*([\\w+#.-]*)[^`]*$")
	fenceCloseRe = regexp.MustCompile("^\\s*(```|~~~)\\s*$")
	sgrRe        = regexp.MustCompile(`\x1b\[[0-9;]*m`)
)

const codeGutter = "\x1b[2m│\x1b[0m "

// renderRich met en forme un texte Markdown pour le terminal : paragraphes
// nettoyés et repliés à la largeur, blocs de code colorés selon leur langage.
func renderRich(s string, width int) []string {
	var out, text, code []string
	lang, fence := "", ""
	flushText := func() {
		if len(text) > 0 {
			out = append(out, wrapLines(cleanMarkdown(strings.Join(text, "\n")), width)...)
			text = nil
		}
	}
	flushCode := func() {
		out = append(out, renderCode(strings.Join(code, "\n"), lang, width)...)
		code = nil
	}
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		switch {
		case fence == "":
			if m := fenceOpenRe.FindStringSubmatch(line); m != nil {
				flushText()
				fence, lang = m[1], strings.ToLower(m[2])
				continue
			}
			text = append(text, line)
		case fenceCloseRe.MatchString(line) && strings.Contains(line, fence):
			flushCode()
			fence = ""
		default:
			code = append(code, line)
		}
	}
	if fence != "" { // bloc non refermé
		flushCode()
	}
	flushText()
	return out
}

// renderCode colore un bloc de code et le présente avec une marge ; les
// lignes trop longues sont repliées sans perdre leur couleur.
func renderCode(code, lang string, width int) []string {
	code = strings.ReplaceAll(strings.Trim(code, "\n"), "\t", "    ")
	if strings.TrimSpace(code) == "" {
		return nil
	}
	colored := highlight(code, lang)
	avail := max(10, width-visibleLen(codeGutter))
	var out []string
	for _, l := range strings.Split(colored, "\n") {
		for _, part := range hardWrap(l, avail) {
			out = append(out, codeGutter+part+reset)
		}
	}
	return out
}

// highlight renvoie le code coloré en séquences ANSI 256 couleurs, ou tel
// quel si le langage est inconnu.
func highlight(code, lang string) string {
	var lexer chroma.Lexer
	switch lang {
	case "", "text", "txt", "plain", "plaintext", "console", "output":
		if lang == "" {
			lexer = lexers.Analyse(code)
		}
	default:
		lexer = lexers.Get(lang)
	}
	if lexer == nil {
		return code
	}
	it, err := chroma.Coalesce(lexer).Tokenise(nil, code)
	if err != nil {
		return code
	}
	var sb strings.Builder
	if err := codeFormatter.Format(&sb, codeStyle, it); err != nil {
		return code
	}
	return strings.TrimRight(sb.String(), "\n")
}

// hardWrap coupe une ligne colorée tous les w caractères visibles, en
// reprenant la couleur en cours au début de chaque morceau.
func hardWrap(line string, w int) []string {
	if visibleLen(line) <= w {
		return []string{line}
	}
	var parts []string
	var cur strings.Builder
	active := "" // dernière séquence de couleur en vigueur
	n := 0
	for i := 0; i < len(line); {
		if loc := sgrRe.FindStringIndex(line[i:]); loc != nil && loc[0] == 0 {
			seq := line[i : i+loc[1]]
			cur.WriteString(seq)
			if seq == reset || seq == "\x1b[0m" {
				active = ""
			} else {
				active += seq
			}
			i += loc[1]
			continue
		}
		if n == w {
			parts = append(parts, cur.String()+reset)
			cur.Reset()
			cur.WriteString(active)
			n = 0
		}
		r, size := utf8.DecodeRuneInString(line[i:])
		cur.WriteRune(r)
		i += size
		n++
	}
	return append(parts, cur.String())
}
