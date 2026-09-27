# vulnkb

<p align="center">
  <img src="docs/logo.svg" alt="vulnkb" width="680">
</p>

Base de connaissances de sécurité consultable en TUI. Collecte des advisories
de vulnérabilités depuis des sources publiques, les normalise dans un format
commun, les stocke dans SQLite avec recherche plein-texte (FTS5), et permet de
les interroger rapidement au clavier.

## Utilisation

Le stockage utilise `github.com/mattn/go-sqlite3` (cgo) : il faut un
compilateur C et le tag de build `sqlite_fts5` pour activer la recherche
plein-texte.

```sh
go mod tidy                                   # dépendances (une fois)
CGO_ENABLED=1 go build -tags sqlite_fts5 -o vulnkb .   # compile

./vulnkb sources         # liste les sources disponibles
./vulnkb sync            # collecte les sources par défaut dans la base
./vulnkb sync osv-npm    # collecte une source précise
./vulnkb watch add nginx # suit un produit (filtre « mes », Ctrl-T dans la TUI)
./vulnkb watch import ~/projets  # suit toutes les dépendances de tes projets
./vulnkb add <url|fichier|->  # ajoute un article ou un texte via Ollama
./vulnkb glossaire       # définitions FR de tous les acronymes
./vulnkb info            # aperçu : taille de la base, entrées par source
./vulnkb theme rose      # thème de couleurs : bleu, rose, vert, cyan, violet, orange (Ctrl-Y dans la TUI)
./vulnkb                 # lance la TUI de recherche (commande par défaut)
```

## Sources

| Source | Contenu | Par défaut |
|--------|---------|------------|
| `cisa-kev` | CVE activement exploitées (catalogue CISA KEV) | oui |
| `osv-go`, `osv-pypi`, `osv-packagist`, `osv-crates`, `osv-maven` | advisories OSV.dev par écosystème : versions affectées et corrigées, CWE, liens | oui |
| `osv-npm` | advisories OSV.dev npm (export de ~200 Mo) | non, `vulnkb sync osv-npm` |
| `certfr` | avis et alertes du CERT-FR (ANSSI), **en français** : systèmes affectés, risques, solution, CVE | oui |
| `nvd` | tous les CVE de la base NVD (NIST) : description, produits et versions (CPE), CWE, score CVSS. Les scores complètent la sévérité des autres sources ; un CVE déjà décrit ailleurs est masqué côté NVD (sauf `src:nvd`) | oui |
| `exploits` | exploits et PoC publics par CVE (Exploit-DB, Metasploit, GitHub) : marqueur et filtre `exploit`, liens dans la fiche | oui |

`certfr` couvre les 3 dernières années par défaut (`VULNKB_CERTFR_DAYS` pour
la profondeur) ; les synchros suivantes ne récupèrent que les bulletins
nouveaux ou révisés, et élargir la fenêtre rattrape automatiquement les plus
anciens. Dans la TUI, une entrée CISA ou OSV dont un CVE est couvert par un
avis CERT-FR affiche un renvoi vers cet avis.

Les entrées OSV `MAL-*` (paquets malveillants) et les advisories retirés sont
ignorés ; une même faille publiée sous plusieurs identifiants (GHSA / GO /
PYSEC) n'est gardée qu'une fois, ses alias restant cherchables.

## Ajouter un article ou un texte

`vulnkb add` transforme un document en fiche de la base, grâce à un LLM local
(Ollama). Trois façons de lui donner le contenu :

```sh
vulnkb add https://blog.example/write-up              # une page web (téléchargée)
vulnkb add ~/notes/faille-vtiger.md                   # un fichier : texte, Markdown ou HTML enregistré
xclip -o | vulnkb add -url https://origine.example -  # un texte envoyé par pipe
vulnkb add -                                          # colle le texte, puis Ctrl-D
```

**Oui, le texte est mis au format de la base automatiquement.** Le modèle lit
le contenu et remplit une fiche : titre, résumé en français, composant, type de
faille, sévérité, versions affectées et corrigées, remédiation, identifiants
CVE/GHSA. La fiche est affichée, puis enregistrée seulement si tu confirmes
(`-y` pour ne pas demander). Elle apparaît ensuite dans la TUI avec la source
`IA`, pour rappeler qu'elle est à relire.

- **Origine** : pour une page web, son URL sert de lien et d'identifiant. Pour
  un texte, indique-la avec `-url` si tu la connais ; sinon l'identifiant est
  calculé à partir du contenu (réimporter le même texte met à jour la fiche au
  lieu de la dupliquer).
- **Garde-fous** : un CVE, un GHSA ou un numéro de version proposé par le
  modèle est retiré s'il n'apparaît pas dans le texte. Le résumé et la
  sévérité, eux, ne sont pas vérifiés : relis-les.
- **Qualité du texte** : plus il est précis (produit, versions, CVE,
  correctif), meilleure est la fiche. Une note de quelques lignes suffit.
- **Réglages** : `-model` ou `VULNKB_MODEL` (défaut `qwen2.5-coder:7b`),
  `-ollama` ou `OLLAMA_HOST` (défaut `http://localhost:11434`). Sans GPU,
  compter de 1 à 4 minutes selon la longueur.

Tests : `CGO_ENABLED=1 go test -tags sqlite_fts5 ./...`

Dans la TUI : tape pour filtrer en direct, `↑`/`↓` pour naviguer, `tab` pour
passer de la liste au détail, `esc` (ou Ctrl-C) pour quitter.

La base est stockée dans `~/.config/vulnkb/vulnkb.db` (ou le dossier courant).

> Note réseau : la collecte contacte `cisa.gov`,
> `osv-vulnerabilities.storage.googleapis.com`, `www.cert.ssi.gouv.fr`,
> `nvd.nist.gov`, `gitlab.com`, `raw.githubusercontent.com` et
> `codeload.github.com` (exploits), et `go mod tidy` récupère les modules. Si ton environnement filtre les sorties réseau (proxy/allowlist),
> autorise ces domaines et le proxy Go, ou utilise `GOPROXY=direct` pour tirer
> les dépendances GitHub.

## Architecture

```
internal/model/    format normalisé (Advisory) — le pivot commun
internal/store/    SQLite + index FTS5, upsert et recherche
internal/source/   interface Source + registre ; une source = un fichier
internal/extract/  article web → texte → fiche via Ollama (commande add)
internal/tui/      interface Bubble Tea + Lipgloss (recherche / liste / fiche / aide)
main.go            CLI : sync, sources, add, watch, info, glossaire, tui
```

## Ajouter une source perso

Une source est un fichier Go dans `internal/source/` qui télécharge des
données et les convertit en fiches (`model.Advisory`). Elle s'enregistre
toute seule : une fois le binaire recompilé, elle apparaît dans
`vulnkb sources` et est collectée par `vulnkb sync`.

### 1. Écrire le fichier

Exemple complet : le flux RSS des bulletins de sécurité d'un éditeur, à
copier dans `internal/source/mon_flux.go` et à adapter (URL, nom, champs) :

```go
package source

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"vulnkb/internal/model"
)

// Flux RSS des bulletins de sécurité d'un éditeur (exemple).
const monFluxURL = "https://editeur.example/security/rss.xml"

func init() { Register(&monFlux{client: &http.Client{Timeout: 30 * time.Second}}) }

type monFlux struct{ client *http.Client }

func (s *monFlux) Name() string { return "mon-flux" }

func (s *monFlux) Fetch(ctx context.Context, since time.Time) ([]model.Advisory, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, monFluxURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("statut %d", resp.StatusCode)
	}

	var feed struct {
		Items []struct {
			Title       string `xml:"title"`
			Link        string `xml:"link"`
			Description string `xml:"description"`
			PubDate     string `xml:"pubDate"`
			GUID        string `xml:"guid"`
		} `xml:"channel>item"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, err
	}

	cveRe := regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	var out []model.Advisory
	for _, it := range feed.Items {
		pub, _ := time.Parse(time.RFC1123Z, it.PubDate)
		id := it.GUID
		if id == "" {
			id = it.Link
		}
		ext := id
		if cves := cveRe.FindAllString(it.Title+" "+it.Description, -1); len(cves) > 0 {
			ext = id + " (" + strings.Join(cves, ", ") + ")"
		}
		out = append(out, model.Advisory{
			ID:         s.Name() + ":" + id,
			Source:     s.Name(),
			ExternalID: ext,
			Title:      it.Title,
			Summary:    it.Description,
			References: []string{it.Link},
			Published:  pub,
			URL:        it.Link,
		})
	}
	return out, nil
}
```

### 2. Remplir la fiche

| Champ | Rôle | Conseil |
|-------|------|---------|
| `ID` | identifiant interne unique et stable | `"<source>:<id d'origine>"` : une nouvelle synchro met la fiche à jour au lieu de la dupliquer |
| `Source` | nom de la source | le même que `Name()` |
| `ExternalID` | identifiant affiché, et ses alias | mets les CVE entre parenthèses : `"BULL-42 (CVE-2026-1234, CVE-2026-5678)"`. C'est ce qui relie la fiche au reste de la base : marqueur « exploitée » (KEV), score NVD, exploits publics, avis CERT-FR, filtre `exploitee` |
| `Title`, `Summary` | titre et description | le résumé peut contenir du Markdown et des blocs de code, ils seront mis en forme |
| `Component` | produit ou paquet touché | c'est ce que cherche le filtre `mes` (liste de surveillance) |
| `Severity` | sévérité | `CRITICAL`, `HIGH`, `MODERATE`/`MEDIUM`, `LOW`, ou un vecteur CVSS 3.x (le score est calculé). Vide : la sévérité NVD des CVE prend le relais |
| `VulnType` | type de faille | codes CWE (`CWE-79`) : leur nom s'affiche en français |
| `AffectedVersions`, `FixedVersions` | versions touchées / corrigées | alimentent le bloc « Que faire » |
| `Remediation` | action recommandée | idem |
| `References`, `URL` | liens | le lien de correctif le plus utile est repris dans « Que faire » |
| `Published` | date de publication | sert au tri par date |

### 3. Options

- `Optional() bool` renvoyant `true` : la source n'est collectée que si on la
  nomme (`vulnkb sync mon-flux`), utile pour une source lourde (voir `osv.go`).
- `Incremental() bool` : le sync lui passe la date de sa dernière collecte
  (`since`) pour ne récupérer que les nouveautés.
- `FetchKnown(ctx, known)` : variante qui reçoit la date de collecte de chaque
  fiche déjà en base, pour ne télécharger que le nouveau ou le révisé
  (voir `certfr.go`).
- Badge et filtre : ajoute ta source à la table `sources` de
  `internal/tui/present.go` (badge de 3 lettres, couleur, nom) et à `srcNames`
  dans `internal/store/query.go` (pour `src:mon-flux`). Sans cela, le badge
  prend les 3 premières lettres du nom, en gris.

### 4. Tester et collecter

```sh
CGO_ENABLED=1 go build -tags sqlite_fts5 -o vulnkb .
./vulnkb sources            # la source apparaît
./vulnkb sync mon-flux      # collecte seulement celle-ci
./vulnkb info               # nombre d'entrées par source
```

Pour un test automatique sans réseau, sers un faux flux avec `httptest`
(voir `certfr_test.go`).

Un document isolé (un write-up, une note) n'a pas besoin de source : utilise
`vulnkb add`.
