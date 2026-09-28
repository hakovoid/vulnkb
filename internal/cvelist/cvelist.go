// Package cvelist lit la liste officielle des CVE (dépôt CVEProject/cvelistV5,
// format JSON 5). Chaque fiche y porte ce que l'émetteur du CVE (le « CNA »)
// a déclaré dès la publication — titre, produits et versions touchés, CWE,
// score — ainsi que les compléments des « ADP », dont l'enrichissement de la
// CISA (Vulnrichment) : score et CWE quand l'émetteur n'en donne pas, et
// l'évaluation SSVC (exploitation constatée, automatisable, impact).
//
// NVD met des semaines, parfois des mois, à analyser un nouveau CVE : en
// attendant, sa fiche n'a ni produit ni version. Ces données comblent le vide.
//
// Téléchargement : un export complet quotidien (~600 Mo, la première fois),
// puis des deltas (quelques Mo par jour).
package cvelist

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"vulnkb/internal/model"
)

const (
	releasesAPI  = "https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=30"
	downloadBase = "https://github.com/CVEProject/cvelistV5/releases/download/"
	userAgent    = "vulnkb (+https://github.com/hakovoid/vulnkb)"
)

// SSVC est l'évaluation de la CISA (Stakeholder-Specific Vulnerability
// Categorization). Exploitation : none, poc (preuve de concept publique) ou
// active (exploitation constatée) ; Automatable : yes/no ; Impact : partial
// ou total.
type SSVC struct {
	Exploitation, Automatable, Impact string
}

// Record est ce que la liste officielle apprend sur un CVE.
type Record struct {
	CVE       string
	Rejected  bool // CVE retiré
	Title     string
	Component string // produits touchés, séparés par « , »
	Affected  string // plages de versions touchées
	Fixed     string // versions correctives
	CWE       string
	Score     model.CVSS // zéro si ni l'émetteur ni la CISA n'en donnent
	SSVC      SSVC
	Published time.Time
}

// Limites d'affichage, comme pour NVD.
const (
	maxProducts = 10
	maxRanges   = 15
)

type metricJSON struct {
	CVSSV40 *cvssJSON `json:"cvssV4_0"`
	CVSSV31 *cvssJSON `json:"cvssV3_1"`
	CVSSV30 *cvssJSON `json:"cvssV3_0"`
	CVSSV20 *cvssJSON `json:"cvssV2_0"`
	Other   *struct {
		Type    string `json:"type"`
		Content struct {
			Options []map[string]string `json:"options"`
		} `json:"content"`
	} `json:"other"`
}

type cvssJSON struct {
	Version      string  `json:"version"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

type affectedJSON struct {
	Vendor        string `json:"vendor"`
	Product       string `json:"product"`
	PackageName   string `json:"packageName"`
	DefaultStatus string `json:"defaultStatus"`
	Versions      []struct {
		Version         string `json:"version"`
		Status          string `json:"status"`
		LessThan        string `json:"lessThan"`
		LessThanOrEqual string `json:"lessThanOrEqual"`
		VersionType     string `json:"versionType"`
	} `json:"versions"`
}

type problemJSON struct {
	Descriptions []struct {
		CWEID string `json:"cweId"`
	} `json:"descriptions"`
}

type containerJSON struct {
	ProviderMetadata struct {
		ShortName string `json:"shortName"`
	} `json:"providerMetadata"`
	Title        string         `json:"title"`
	Affected     []affectedJSON `json:"affected"`
	ProblemTypes []problemJSON  `json:"problemTypes"`
	Metrics      []metricJSON   `json:"metrics"`
}

type recordJSON struct {
	Metadata struct {
		ID            string `json:"cveId"`
		State         string `json:"state"`
		Assigner      string `json:"assignerShortName"`
		DatePublished string `json:"datePublished"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA containerJSON   `json:"cna"`
		ADP []containerJSON `json:"adp"`
	} `json:"containers"`
}

// Parse décode une fiche CVE au format JSON 5.
func Parse(r io.Reader) (Record, error) {
	var j recordJSON
	if err := json.NewDecoder(r).Decode(&j); err != nil {
		return Record{}, err
	}
	rec := Record{CVE: j.Metadata.ID}
	if rec.CVE == "" {
		return rec, fmt.Errorf("fiche sans identifiant")
	}
	if j.Metadata.State == "REJECTED" {
		rec.Rejected = true
		return rec, nil
	}
	cna := j.Containers.CNA
	rec.Title = strings.Join(strings.Fields(cna.Title), " ")
	rec.Published, _ = time.Parse(time.RFC3339, j.Metadata.DatePublished)

	products, affected, fixed := summarize(cna.Affected)
	cwes := cweList(cna.ProblemTypes)
	score, ok := bestScore(cna.Metrics, "CNA "+j.Metadata.Assigner)
	for _, adp := range j.Containers.ADP {
		name := adp.ProviderMetadata.ShortName
		if len(products) == 0 {
			products, affected, fixed = summarize(adp.Affected)
		}
		if cwes == "" {
			cwes = cweList(adp.ProblemTypes)
		}
		if !ok {
			score, ok = bestScore(adp.Metrics, name)
		}
		if name == "CISA-ADP" {
			rec.SSVC = ssvc(adp.Metrics)
		}
	}
	rec.Component = strings.Join(products, ", ")
	rec.Affected = strings.Join(affected, " ; ")
	rec.Fixed = strings.Join(fixed, " ; ")
	rec.CWE = cwes
	if ok {
		score.CVE, score.CWE = rec.CVE, cwes
		rec.Score = score
	}
	return rec, nil
}

// bestScore retient un score CVSS : 3.1, puis 3.0, 4.0 et 2.0 (le même ordre
// que pour NVD).
func bestScore(ms []metricJSON, source string) (model.CVSS, bool) {
	for _, pick := range []func(metricJSON) *cvssJSON{
		func(m metricJSON) *cvssJSON { return m.CVSSV31 },
		func(m metricJSON) *cvssJSON { return m.CVSSV30 },
		func(m metricJSON) *cvssJSON { return m.CVSSV40 },
		func(m metricJSON) *cvssJSON { return m.CVSSV20 },
	} {
		for _, m := range ms {
			c := pick(m)
			if c == nil || c.BaseScore <= 0 {
				continue
			}
			level := model.ParseSeverity(c.BaseSeverity).Level
			if level == model.SevUnknown {
				level = model.LevelForScore(c.BaseScore)
			}
			return model.CVSS{Score: c.BaseScore, Level: level, Version: c.Version,
				Vector: c.VectorString, Source: source}, true
		}
	}
	return model.CVSS{}, false
}

func ssvc(ms []metricJSON) SSVC {
	var s SSVC
	for _, m := range ms {
		if m.Other == nil || m.Other.Type != "ssvc" {
			continue
		}
		for _, o := range m.Other.Content.Options {
			for k, v := range o {
				switch strings.ToLower(k) {
				case "exploitation":
					s.Exploitation = strings.ToLower(v)
				case "automatable":
					s.Automatable = strings.ToLower(v)
				case "technical impact":
					s.Impact = strings.ToLower(v)
				}
			}
		}
	}
	return s
}

func cweList(pts []problemJSON) string {
	seen := map[string]bool{}
	var out []string
	for _, p := range pts {
		for _, d := range p.Descriptions {
			if strings.HasPrefix(d.CWEID, "CWE-") && !seen[d.CWEID] {
				seen[d.CWEID] = true
				out = append(out, d.CWEID)
			}
		}
	}
	return strings.Join(out, ", ")
}

// vague sont les valeurs de version qui ne disent rien.
func vague(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "*", "-", "n/a", "unspecified", "not specified", "unknown", "all", "all versions":
		return true
	}
	// une phrase n'est pas un numéro de version (« R 00/01/02 CPU firmware
	// versions '20' and earlier, … »)
	return len(v) > 40
}

// exactTypes sont les types de version qui ne sont pas des numéros lisibles
// (empreintes git du noyau Linux, etc.).
var exactTypes = map[string]bool{"git": true, "original_commit_for_fix": true, "patch": true, "date": true}

// summarize tire de la section « affected » les produits touchés, les plages
// de versions vulnérables et les versions correctives.
func summarize(items []affectedJSON) (products, affected, fixed []string) {
	seenP, seenA, seenF := map[string]bool{}, map[string]bool{}, map[string]bool{}
	add := func(list *[]string, seen map[string]bool, v string, limit int) {
		if v != "" && !seen[v] && len(*list) < limit {
			seen[v] = true
			*list = append(*list, v)
		}
	}
	for _, it := range items {
		name := productName(it.Vendor, it.Product, it.PackageName)
		if name == "" {
			continue
		}
		// le paquet d'abord (Red Hat : « pcp » dans « Red Hat Enterprise
		// Linux 9 ») : c'est lui que l'on cherche
		if pkg := strings.TrimSpace(it.PackageName); !vague(pkg) && !strings.Contains(strings.ToLower(name), strings.ToLower(pkg)) {
			add(&products, seenP, pkg, maxProducts)
		}
		add(&products, seenP, name, maxProducts)
		for _, v := range it.Versions {
			if exactTypes[v.VersionType] {
				continue
			}
			switch v.Status {
			case "affected":
				var r []string
				// « 1.8.31 < 1.8.31 » : convention de certains émetteurs pour
				// « avant 1.8.31 »
				if !vague(v.Version) && !strings.Contains(v.Version, "*") && v.Version != v.LessThan {
					// une version seule, quand tout est touché par défaut, ouvre
					// une plage (noyau Linux : « touché depuis 4.15 »)
					if v.LessThan != "" || v.LessThanOrEqual != "" || it.DefaultStatus == "affected" {
						r = append(r, ">= "+v.Version)
					} else {
						r = append(r, "= "+v.Version)
					}
				}
				switch {
				case v.LessThan != "" && !vague(v.LessThan):
					r = append(r, "< "+v.LessThan)
					add(&fixed, seenF, name+" "+v.LessThan, maxRanges)
				case v.LessThanOrEqual != "" && !vague(v.LessThanOrEqual):
					r = append(r, "<= "+v.LessThanOrEqual)
				}
				if len(r) > 0 {
					add(&affected, seenA, name+" "+strings.Join(r, " "), maxRanges)
				}
			case "unaffected":
				// « non touché à partir de X » quand le reste est touché : X corrige
				if it.DefaultStatus == "affected" && !vague(v.Version) && !strings.Contains(v.Version, "*") {
					add(&fixed, seenF, name+" "+v.Version, maxRanges)
				}
			}
		}
	}
	return products, affected, fixed
}

// productName compose le nom affiché : « vendor product », sans répéter
// l'éditeur quand le produit le contient déjà ; le paquet à défaut de produit.
func productName(vendor, product, pkg string) string {
	vendor, product = strings.TrimSpace(vendor), strings.TrimSpace(product)
	if vague(product) {
		product = strings.TrimSpace(pkg)
	}
	if vague(product) {
		return ""
	}
	lp, lv := strings.ToLower(product), strings.ToLower(vendor)
	if vague(vendor) || strings.Contains(lp, lv) || strings.Fields(lp)[0] == strings.Fields(lv)[0] {
		return product // « Apache Software Foundation » + « Apache Roller »
	}
	return vendor + " " + product
}

// ReadZip lit toutes les fiches (.json) d'une archive et appelle emit pour
// chacune. Une fiche illisible est ignorée.
func ReadZip(zr *zip.Reader, emit func(Record) error) error {
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") || !strings.Contains(f.Name, "CVE-") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		rec, err := Parse(rc)
		rc.Close()
		if err != nil {
			continue
		}
		if err := emit(rec); err != nil {
			return err
		}
	}
	return nil
}

// Release est une publication du dépôt : un export complet du jour et un
// delta cumulé depuis minuit (UTC).
type Release struct {
	Day   string // AAAA-MM-JJ
	Full  string // URL de l'export complet
	Delta string // URL du delta du jour, "" si absent
}

// Latest renvoie la publication horaire la plus récente.
func Latest(ctx context.Context, client *http.Client) (Release, error) {
	body, err := get(ctx, client, releasesAPI)
	if err != nil {
		return Release{}, err
	}
	var rels []struct {
		Tag    string `json:"tag_name"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &rels); err != nil {
		return Release{}, fmt.Errorf("liste des publications : %w", err)
	}
	for _, r := range rels {
		var rel Release
		for _, a := range r.Assets {
			switch {
			case strings.Contains(a.Name, "_all_CVEs_at_midnight"):
				rel.Full = a.URL
				rel.Day = a.Name[:10]
			case strings.Contains(a.Name, "_delta_CVEs_at_") && !strings.Contains(a.Name, "end_of_day"):
				rel.Delta = a.URL
			}
		}
		if rel.Full != "" {
			return rel, nil
		}
	}
	return Release{}, fmt.Errorf("aucune publication complète trouvée")
}

// EndOfDayURL est l'adresse du delta de fin de journée (toutes les fiches
// ajoutées ou modifiées ce jour-là, en UTC).
func EndOfDayURL(day string) string {
	return downloadBase + "cve_" + day + "_at_end_of_day/" + day + "_delta_CVEs_at_end_of_day.zip"
}

// ErrNotFound signale une publication absente (pas encore mise en ligne).
var ErrNotFound = fmt.Errorf("publication absente")

// FetchDelta télécharge un delta (quelques Mo) et en lit les fiches.
func FetchDelta(ctx context.Context, client *http.Client, url string, emit func(Record) error) error {
	body, err := get(ctx, client, url)
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return fmt.Errorf("delta : %w", err)
	}
	return ReadZip(zr, emit)
}

// FetchFull télécharge l'export complet (~600 Mo, un zip contenant un zip)
// dans des fichiers temporaires, supprimés ensuite, et en lit les fiches.
func FetchFull(ctx context.Context, client *http.Client, url string, emit func(Record) error) error {
	outer, err := download(ctx, client, url)
	if err != nil {
		return err
	}
	defer os.Remove(outer)
	oz, err := zip.OpenReader(outer)
	if err != nil {
		return fmt.Errorf("export : %w", err)
	}
	defer oz.Close()
	var inner *zip.File
	for _, f := range oz.File {
		if strings.HasSuffix(f.Name, ".zip") {
			inner = f
		}
	}
	if inner == nil {
		return fmt.Errorf("export : archive interne absente")
	}
	tmp, err := os.CreateTemp("", "vulnkb-cves-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	rc, err := inner.Open()
	if err == nil {
		_, err = io.Copy(tmp, rc)
		rc.Close()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("export : %w", err)
	}
	zr, err := zip.OpenReader(tmp.Name())
	if err != nil {
		return fmt.Errorf("export : %w", err)
	}
	defer zr.Close()
	return ReadZip(&zr.Reader, emit)
}

func request(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s : statut %d", url, resp.StatusCode)
	}
	return resp, nil
}

func get(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	resp, err := request(ctx, client, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// download enregistre url dans un fichier temporaire et renvoie son chemin.
func download(ctx context.Context, client *http.Client, url string) (string, error) {
	resp, err := request(ctx, client, url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	f, err := os.CreateTemp("", "vulnkb-cvelist-*.zip")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("téléchargement : %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
