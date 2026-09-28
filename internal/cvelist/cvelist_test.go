package cvelist

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const hugo = `{"cveMetadata":{"cveId":"CVE-2026-100691","state":"PUBLISHED","assignerShortName":"VulnCheck","datePublished":"2026-09-26T10:00:00.000Z"},
"containers":{"cna":{"title":"Hugo before 0.166.0 Stored XSS",
 "affected":[{"vendor":"gohugoio","product":"hugo","defaultStatus":"unaffected","versions":[{"version":"0.75.0","lessThan":"0.166.0","status":"affected","versionType":"semver"}]}],
 "problemTypes":[{"descriptions":[{"cweId":"CWE-79"}]}],
 "metrics":[{"cvssV3_1":{"version":"3.1","baseScore":5.4,"baseSeverity":"MEDIUM","vectorString":"CVSS:3.1/AV:N"}}]},
"adp":[{"providerMetadata":{"shortName":"CISA-ADP"},"metrics":[{"other":{"type":"ssvc","content":{"options":[{"Exploitation":"poc"},{"Automatable":"yes"},{"Technical Impact":"total"}]}}}]}]}}`

// noyau Linux : une version « touchée » seule ouvre une plage, les empreintes
// git sont ignorées, les versions « non touchées » sont des correctifs.
const kernel = `{"cveMetadata":{"cveId":"CVE-2026-97509","state":"PUBLISHED","assignerShortName":"Linux"},
"containers":{"cna":{"title":"thunderbolt: keep reference",
 "affected":[
  {"vendor":"Linux","product":"Linux","defaultStatus":"unaffected","versions":[{"version":"1b2c3d","lessThan":"4e5f6a","status":"affected","versionType":"git"}]},
  {"vendor":"Linux","product":"Linux","defaultStatus":"affected","versions":[{"version":"4.15","status":"affected"},{"version":"0","lessThan":"4.15","status":"unaffected","versionType":"semver"},{"version":"6.12.111","lessThanOrEqual":"6.12.*","status":"unaffected","versionType":"semver"}]}]},
"adp":[{"providerMetadata":{"shortName":"CISA-ADP"},"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":7.8,"baseSeverity":"HIGH"}}],"problemTypes":[{"descriptions":[{"cweId":"CWE-416"}]}]}]}}`

// Red Hat : le paquet passe avant les produits (versions de la distribution)
const redhat = `{"cveMetadata":{"cveId":"CVE-2026-16529","state":"PUBLISHED","assignerShortName":"redhat"},
"containers":{"cna":{"title":"Pcp: denial of service",
 "affected":[{"vendor":"Red Hat","product":"Red Hat Enterprise Linux 9","packageName":"pcp","defaultStatus":"affected","versions":[{"version":"0:6.3.7-8.el9","lessThan":"*","status":"unaffected","versionType":"rpm"}]},
  {"vendor":"Apache Software Foundation","product":"Apache Roller","versions":[{"version":"1.8.31","lessThan":"1.8.31","status":"affected"},{"version":"Not specified","status":"affected"}]}]}}}`

const rejected = `{"cveMetadata":{"cveId":"CVE-2026-1","state":"REJECTED"},"containers":{"cna":{}}}`

func parse(t *testing.T, s string) Record {
	t.Helper()
	r, err := Parse(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestParse(t *testing.T) {
	r := parse(t, hugo)
	if r.Title != "Hugo before 0.166.0 Stored XSS" || r.Component != "gohugoio hugo" ||
		r.Affected != "gohugoio hugo >= 0.75.0 < 0.166.0" || r.Fixed != "gohugoio hugo 0.166.0" || r.CWE != "CWE-79" {
		t.Errorf("hugo : %+v", r)
	}
	if r.Score.Score != 5.4 || r.Score.Level != 2 || r.Score.Source != "CNA VulnCheck" || r.Score.CVE != r.CVE {
		t.Errorf("score : %+v", r.Score)
	}
	if r.SSVC != (SSVC{"poc", "yes", "total"}) || r.Published.IsZero() {
		t.Errorf("SSVC : %+v", r.SSVC)
	}

	k := parse(t, kernel)
	if k.Affected != "Linux >= 4.15" || k.Fixed != "Linux 6.12.111" {
		t.Errorf("noyau : affected %q fixed %q", k.Affected, k.Fixed)
	}
	if k.Score.Source != "CISA-ADP" || k.Score.Score != 7.8 || k.CWE != "CWE-416" {
		t.Errorf("complément CISA : %+v %q", k.Score, k.CWE)
	}

	rh := parse(t, redhat)
	if rh.Component != "pcp, Red Hat Enterprise Linux 9, Apache Roller" {
		t.Errorf("produits : %q", rh.Component)
	}
	if rh.Fixed != "Red Hat Enterprise Linux 9 0:6.3.7-8.el9 ; Apache Roller 1.8.31" || rh.Affected != "Apache Roller < 1.8.31" {
		t.Errorf("versions : affected %q fixed %q", rh.Affected, rh.Fixed)
	}

	if !parse(t, rejected).Rejected {
		t.Error("CVE rejeté non signalé")
	}
}

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, _ := zw.Create(name)
		w.Write([]byte(body))
	}
	zw.Close()
	return buf.Bytes()
}

func TestFetch(t *testing.T) {
	inner := zipOf(t, map[string]string{"cves/2026/CVE-2026-100691.json": hugo, "cves/delta.json": "{}", "cves/README.md": "x"})
	full := zipOf(t, map[string]string{"cves.zip": string(inner)})
	delta := zipOf(t, map[string]string{"deltaCves/CVE-2026-97509.json": kernel})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/full.zip.zip":
			w.Write(full)
		case "/delta.zip":
			w.Write(delta)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var got []string
	emit := func(r Record) error { got = append(got, r.CVE); return nil }
	ctx := context.Background()
	if err := FetchFull(ctx, srv.Client(), srv.URL+"/full.zip.zip", emit); err != nil {
		t.Fatal(err)
	}
	if err := FetchDelta(ctx, srv.Client(), srv.URL+"/delta.zip", emit); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "CVE-2026-100691 CVE-2026-97509" {
		t.Errorf("fiches lues : %v", got)
	}
	if err := FetchDelta(ctx, srv.Client(), srv.URL+"/absent.zip", emit); err != ErrNotFound {
		t.Errorf("delta absent : %v", err)
	}
	if !strings.HasSuffix(EndOfDayURL("2026-09-27"), "/cve_2026-09-27_at_end_of_day/2026-09-27_delta_CVEs_at_end_of_day.zip") {
		t.Error(EndOfDayURL("2026-09-27"))
	}
}
