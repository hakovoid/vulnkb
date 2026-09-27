package tui

import (
	"strings"
	"testing"
)

func TestParseSeverity(t *testing.T) {
	cases := map[string]severity{
		"CRITICAL":        {level: 4},
		"Critical":        {level: 4},
		"MODERATE":        {level: 2},
		"LOW":             {level: 1},
		"Known Exploited": {level: 0},
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": {level: 4, score: "9.8"},
	}
	for raw, want := range cases {
		if got := parseSeverity(raw); got != want {
			t.Errorf("%q: obtenu %+v, attendu %+v", raw, got, want)
		}
	}
}

func TestCleanMarkdown(t *testing.T) {
	in := "### Impact\r\nA **stored** XSS in `render()`.\n\n\n\n- see [the fix](https://x.test/fix)\n* <b>version</b> <= 1.2\n```go\ncode()\n```\n[https://a.test](https://a.test)"
	got := cleanMarkdown(in)
	for _, want := range []string{bold + "Impact" + reset, "A stored XSS in " + inlineCode + "render()" + reset + ".", "• see the fix (https://x.test/fix)", "• version <= 1.2", "code()", "https://a.test"} {
		if !strings.Contains(got, want) {
			t.Errorf("sortie sans %q:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"###", "**", "`", "<b>", "\n\n\n", "](", "\r"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("sortie contient %q:\n%s", unwanted, got)
		}
	}
}

func TestDescribeCWEsAndPrimaryID(t *testing.T) {
	if got := describeCWEs("CWE-79, CWE-99999"); got != "CWE-79 (XSS, injection de script dans la page), CWE-99999" {
		t.Errorf("describeCWEs: %q", got)
	}
	if got := primaryID("GHSA-22fx-6r9m-r8h9 (CVE-2023-29659)"); got != "GHSA-22fx-6r9m-r8h9" {
		t.Errorf("primaryID: %q", got)
	}
	if got := primaryID("CVE-2026-1"); got != "CVE-2026-1" {
		t.Errorf("primaryID sans alias: %q", got)
	}
}

func TestShortAliases(t *testing.T) {
	if got := shortAliases("CERTFR-1 (CVE-1, CVE-2, CVE-3, CVE-4)", 2); got != "CERTFR-1 (CVE-1, CVE-2, … et 2 autres)" {
		t.Errorf("shortAliases: %q", got)
	}
	if got := shortAliases("GHSA-x (CVE-1)", 2); got != "GHSA-x (CVE-1)" {
		t.Errorf("shortAliases court: %q", got)
	}
}

func TestShortRemediation(t *testing.T) {
	cisa := "Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 guidance. Discontinue use if unavailable."
	if got := shortRemediation(cisa); !strings.Contains(got, "éditeur") || strings.Contains(got, "BOD") {
		t.Errorf("boilerplate non raccourci: %q", got)
	}
	own := "Mettre à jour gitea.dev en 1.27.1 ou plus."
	if shortRemediation(own) != own {
		t.Errorf("remédiation propre modifiée: %q", shortRemediation(own))
	}
}
