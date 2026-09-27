# vulnkb

```ansi
[1;38;5;39m░█░█░█░█░█░░░█▀█░█░█░█▀▄[0m
[1;38;5;75m░▀▄▀░█░█░█░░░█░█░█▀▄░█▀▄[0m
[1;38;5;111m░░▀░░▀▀▀░▀▀▀░▀░▀░▀░▀░▀▀░[0m
[38;5;244m   base de connaissances de sécurité · dans le terminal[0m
```

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
./vulnkb watch add nginx # suit un produit (filtre « mes » dans la recherche)
./vulnkb add <url>       # ajoute un article (write-up, blog) via Ollama
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

## Articles (extraction IA)

`vulnkb add <url>` télécharge un article, en extrait le texte principal et le
confie à un LLM local (Ollama) qui remplit une fiche : titre, résumé en
français, composant, type de faille, sévérité, versions, remédiation,
identifiants CVE/GHSA. La fiche est affichée puis enregistrée après
confirmation (`-y` pour sauter la question), avec la source `article-ia`.

Garde-fous : les identifiants CVE/GHSA et les numéros de version proposés par
le modèle sont écartés s'ils n'apparaissent pas dans l'article. Le reste
(résumé, sévérité) reste à relire.

Réglages : `-model` ou `VULNKB_MODEL` (défaut `qwen2.5-coder:7b`), `-ollama` ou
`OLLAMA_HOST` (défaut `http://localhost:11434`). Sans GPU, compter quelques
minutes par article.

Tests : `CGO_ENABLED=1 go test -tags sqlite_fts5 ./...`

Dans la TUI : tape pour filtrer en direct, `↑`/`↓` pour naviguer, `tab` pour
passer de la liste au détail, `esc` (ou Ctrl-C) pour quitter.

La base est stockée dans `~/.config/vulnkb/vulnkb.db` (ou le dossier courant).

> Note réseau : la collecte contacte `cisa.gov`,
> `osv-vulnerabilities.storage.googleapis.com`, `www.cert.ssi.gouv.fr` et `nvd.nist.gov`, et `go mod tidy` récupère les
> modules. Si ton environnement filtre les sorties réseau (proxy/allowlist),
> autorise ces domaines et le proxy Go, ou utilise `GOPROXY=direct` pour tirer
> les dépendances GitHub.

## Architecture

```
internal/model/    format normalisé (Advisory) — le pivot commun
internal/store/    SQLite + index FTS5, upsert et recherche
internal/source/   interface Source + registre ; une source = un fichier
internal/extract/  article web → texte → fiche via Ollama (commande add)
internal/tui/      interface Bubble Tea + Lipgloss (recherche / liste / fiche / aide)
main.go            CLI : sync, sources, add, tui
```

## Ajouter une source

Une source implémente l'interface `source.Source` (méthodes `Name()` et
`Fetch()`) et s'enregistre dans un `init()`. Voir `internal/source/cisakev.go`
comme modèle. Une source lourde peut implémenter `Optional()` pour être exclue
du sync par défaut (voir `osv.go`). Pistes : NVD (CVSS/CWE), flux RSS
d'éditeurs.
