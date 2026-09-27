package tui

import (
	"strings"
	"testing"
)

func TestRenderRich(t *testing.T) {
	in := "### Summary\nThe `api_server.py` route is open.\n\n```python\n@app.post(\"/api/ops/check-email\")\nasync def ops_check_email():\n\treturn run(\"email_reader.py\")\n```\nAfter the code.\n```\nplain block without language\n```"
	lines := renderRich(in, 60)
	joined := strings.Join(lines, "\n")

	var code []string
	for _, l := range lines {
		if strings.HasPrefix(l, codeGutter) {
			code = append(code, l)
		}
	}
	if len(code) != 4 {
		t.Fatalf("attendu 4 lignes de code (3 python + 1 sans langage), obtenu %d:\n%s", len(code), joined)
	}
	if !strings.Contains(code[0], "\x1b[38;5;") {
		t.Errorf("code python non coloré: %q", code[0])
	}
	if !strings.Contains(stripANSI(code[2]), "    return run(") {
		t.Errorf("tabulation/indentation perdue: %q", stripANSI(code[2]))
	}
	for _, want := range []string{"Summary", inlineCode + "api_server.py" + reset, "After the code."} {
		if !strings.Contains(joined, want) {
			t.Errorf("sortie sans %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "```") {
		t.Errorf("clôtures de bloc restées visibles:\n%s", joined)
	}
}

func TestHardWrapKeepsColor(t *testing.T) {
	line := "\x1b[38;5;197m" + strings.Repeat("a", 25) + "\x1b[0m" + strings.Repeat("b", 5)
	parts := hardWrap(line, 10)
	if len(parts) != 3 {
		t.Fatalf("attendu 3 morceaux, obtenu %d: %q", len(parts), parts)
	}
	for i, p := range parts {
		if visibleLen(p) > 10 {
			t.Errorf("morceau %d trop long: %d", i, visibleLen(p))
		}
	}
	if !strings.HasPrefix(parts[1], "\x1b[38;5;197m") {
		t.Errorf("couleur non reprise au début du morceau 2: %q", parts[1])
	}
	if strings.Join([]string{stripANSI(parts[0]), stripANSI(parts[1]), stripANSI(parts[2])}, "") != strings.Repeat("a", 25)+strings.Repeat("b", 5) {
		t.Errorf("contenu altéré: %q", parts)
	}
}

func TestUnknownLanguageStaysPlain(t *testing.T) {
	if got := highlight("some output", "text"); got != "some output" {
		t.Errorf("bloc text coloré: %q", got)
	}
	if got := highlight("x", "langage-inexistant"); got != "x" {
		t.Errorf("langage inconnu: %q", got)
	}
}

func stripANSI(s string) string { return sgrRe.ReplaceAllString(s, "") }
