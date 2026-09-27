package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vulnkb/internal/model"
	"vulnkb/internal/store"
)

func TestMarkdownHTMLIsSafe(t *testing.T) {
	src := "### Impact\nA **stored** XSS in `render()` <script>alert(1)</script>.\n\n" +
		"- voir [le correctif](https://x.test/fix?a=1&b=2)\n- [piège](javascript:alert(1))\n\n" +
		"```js\nif (a < b) { run(\"x\") }\n```\nSource : https://blog.example/post."
	got := string(markdownHTML(src))
	for _, want := range []string{
		"<h4>Impact</h4>", "<strong>stored</strong>", "<code>render()</code>",
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		`<a href="https://x.test/fix?a=1&amp;b=2">le correctif</a>`,
		"<pre><code>if (a &lt; b) { run(&#34;x&#34;) }</code></pre>",
		`<a href="https://blog.example/post">https://blog.example/post</a>.`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("sortie sans %q :\n%s", want, got)
		}
	}
	if strings.Contains(got, "<script") || strings.Contains(got, `href="javascript`) {
		t.Errorf("contenu actif non neutralisé :\n%s", got)
	}
}

func TestExportReport(t *testing.T) {
	s, err := store.Open(t.TempDir() + "/x.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Upsert([]model.Advisory{
		{ID: "cisa-kev:CVE-2021-44228", Source: "cisa-kev", ExternalID: "CVE-2021-44228", Title: "Log4Shell", Severity: "CRITICAL"},
		{ID: "osv:g", Source: "osv", ExternalID: "GHSA-g (CVE-2021-44228)", Title: "log4j-core <b>RCE</b>", Severity: "CRITICAL",
			Component: "Maven org.apache.logging.log4j:log4j-core", FixedVersions: "log4j-core 2.17.1", VulnType: "CWE-502",
			Summary: "Lookup JNDI.", References: []string{"https://logging.apache.org/log4j/2.x/security.html", "javascript:alert(1)"}},
		{ID: "osv:h", Source: "osv", ExternalID: "GHSA-h", Title: "mineure", Severity: "LOW"},
	})
	s.ReplaceExploits([]model.ExploitRef{{CVE: "CVE-2021-44228", Kind: "msf", Title: "Log4Shell HTTP Scanner", URL: "https://r7/mod"}})
	s.RefreshDerived()

	out := filepath.Join(t.TempDir(), "rapport.html")
	path, n, total, err := ExportSearch(s, "log4", store.SortSeverity, 1, out)
	if err != nil {
		t.Fatal(err)
	}
	if path != out || n != 1 || total != 2 {
		t.Errorf("export : %s, %d/%d", path, n, total)
	}
	path, n, _, err = ExportSearch(s, "", store.SortSeverity, 0, out)
	if err != nil || n != 3 {
		t.Fatalf("export complet : %d, %v", n, err)
	}
	b, _ := os.ReadFile(path)
	page := string(b)
	for _, want := range []string{
		"<title>vulnkb — Toute la base</title>", "Que faire", "Mettre à jour : log4j-core 2.17.1",
		"EXPLOITÉE (KEV)", "EXPLOIT PUBLIC", "Log4Shell HTTP Scanner", "CWE-502 (désérialisation",
		"log4j-core &lt;b&gt;RCE&lt;/b&gt;", `href="https://logging.apache.org/log4j/2.x/security.html"`,
		`<a href="#f1">`, "exploitées activement",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("rapport sans %q", want)
		}
	}
	if strings.Contains(page, "javascript:alert") || strings.Contains(page, "<b>RCE</b>") {
		t.Error("contenu non neutralisé dans le rapport")
	}

	a, _ := s.Search("mineure", 1)
	p2, err := ExportAdvisory(s, a[0], filepath.Join(t.TempDir(), "fiche.html"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(p2)
	if !strings.Contains(string(b), "GHSA-h") || strings.Contains(string(b), "<nav>") {
		t.Error("fiche seule : contenu ou sommaire incorrect")
	}
	if got := exportPath("mes sev:high+"); !strings.Contains(got, "vulnkb-mes-sev-high-") {
		t.Errorf("nom de fichier : %s", got)
	}
}
