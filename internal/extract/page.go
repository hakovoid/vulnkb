// Package extract transforme un article web (billet de blog, write-up) en
// model.Advisory à l'aide d'un LLM local. Le HTML est réduit en texte brut
// sans dépendance externe, puis confié au modèle avec un schéma JSON imposé.
package extract

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Page est le contenu utile d'un article téléchargé.
type Page struct {
	URL       string
	Title     string
	Text      string
	Links     []string // liens externes cités dans l'article
	Published time.Time
}

const maxPageBytes = 5 << 20

// Fetch télécharge une page HTML et en extrait le contenu.
func Fetch(ctx context.Context, client *http.Client, pageURL string) (Page, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return Page{}, err
	}
	req.Header.Set("User-Agent", "vulnkb (+https://github.com/hakovoid/vulnkb)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp, err := client.Do(req)
	if err != nil {
		return Page{}, fmt.Errorf("téléchargement %s: %w", pageURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Page{}, fmt.Errorf("téléchargement %s: statut %d", pageURL, resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.Contains(ct, "html") {
		return Page{}, fmt.Errorf("%s n'est pas une page HTML (%s)", pageURL, ct)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPageBytes))
	if err != nil {
		return Page{}, err
	}
	final := resp.Request.URL.String()
	return ParsePage(final, string(body)), nil
}

var (
	dropTags = func() []*regexp.Regexp {
		var out []*regexp.Regexp
		for _, t := range []string{"script", "style", "noscript", "svg", "nav", "header", "footer", "form", "iframe", "template"} {
			out = append(out, regexp.MustCompile(`(?is)<`+t+`\b[^>]*>.*?</`+t+`\s*>`))
		}
		return out
	}()
	commentRe   = regexp.MustCompile(`(?s)<!--.*?-->`)
	containers  = []*regexp.Regexp{regexp.MustCompile(`(?is)<article\b[^>]*>(.*)</article>`), regexp.MustCompile(`(?is)<main\b[^>]*>(.*)</main>`), regexp.MustCompile(`(?is)<body\b[^>]*>(.*)</body>`)}
	blockRe     = regexp.MustCompile(`(?i)</?(p|div|br|li|ul|ol|h[1-6]|tr|pre|blockquote|section|figure|figcaption|table)\b[^>]*>`)
	tagRe       = regexp.MustCompile(`(?s)<[^>]+>`)
	spaceRe     = regexp.MustCompile(`[ \t\r\f\v\x{00a0}]+`)
	blankRe     = regexp.MustCompile(`\n{3,}`)
	hrefRe      = regexp.MustCompile(`(?is)<a\b[^>]*?\shref\s*=\s*["']([^"']+)["']`)
	titleRe     = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	timeRe      = regexp.MustCompile(`(?is)<time\b[^>]*\sdatetime\s*=\s*["']([^"']+)["']`)
	maxLinks    = 20
	dateLayouts = []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"}
)

// ParsePage réduit un document HTML à son texte principal.
func ParsePage(pageURL, doc string) Page {
	p := Page{URL: pageURL}

	p.Title = metaContent(doc, "og:title")
	if p.Title == "" {
		if m := titleRe.FindStringSubmatch(doc); m != nil {
			p.Title = cleanInline(m[1])
		}
	}
	p.Published = parseDate(metaContent(doc, "article:published_time"))
	if p.Published.IsZero() {
		if m := timeRe.FindStringSubmatch(doc); m != nil {
			p.Published = parseDate(m[1])
		}
	}

	body := commentRe.ReplaceAllString(doc, "")
	for _, re := range dropTags {
		body = re.ReplaceAllString(body, "")
	}
	for _, re := range containers {
		if m := re.FindStringSubmatch(body); m != nil {
			body = m[1]
			break
		}
	}

	p.Links = externalLinks(pageURL, body)
	p.Text = htmlToText(body)
	return p
}

func htmlToText(s string) string {
	s = blockRe.ReplaceAllString(s, "\n")
	s = tagRe.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(spaceRe.ReplaceAllString(l, " "))
	}
	s = strings.Join(lines, "\n")
	return strings.TrimSpace(blankRe.ReplaceAllString(s, "\n\n"))
}

func cleanInline(s string) string {
	return strings.TrimSpace(spaceRe.ReplaceAllString(html.UnescapeString(tagRe.ReplaceAllString(s, " ")), " "))
}

// externalLinks renvoie les liens http(s) vers d'autres sites, dédoublonnés.
func externalLinks(pageURL, body string) []string {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
		u, err := base.Parse(html.UnescapeString(strings.TrimSpace(m[1])))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == base.Host {
			continue
		}
		u.Fragment = ""
		s := u.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
			if len(out) == maxLinks {
				break
			}
		}
	}
	return out
}

// metaContent lit <meta property|name="key" content="…">, quel que soit
// l'ordre des attributs.
func metaContent(doc, key string) string {
	k := regexp.QuoteMeta(key)
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`(?is)<meta\b[^>]*?(?:property|name)\s*=\s*["']` + k + `["'][^>]*?\scontent\s*=\s*["']([^"']*)["']`),
		regexp.MustCompile(`(?is)<meta\b[^>]*?\scontent\s*=\s*["']([^"']*)["'][^>]*?(?:property|name)\s*=\s*["']` + k + `["']`),
	} {
		if m := re.FindStringSubmatch(doc); m != nil {
			return cleanInline(m[1])
		}
	}
	return ""
}

func parseDate(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, l := range dateLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
