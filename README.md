# vulnkb

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
./vulnkb                 # lance la TUI de recherche (commande par défaut)
```

## Sources

| Source | Contenu | Par défaut |
|--------|---------|------------|
| `cisa-kev` | CVE activement exploitées (catalogue CISA KEV) | oui |
| `osv-go`, `osv-pypi`, `osv-packagist`, `osv-crates`, `osv-maven` | advisories OSV.dev par écosystème : versions affectées et corrigées, CWE, liens | oui |
| `osv-npm` | advisories OSV.dev npm (export de ~200 Mo) | non, `vulnkb sync osv-npm` |

Les entrées OSV `MAL-*` (paquets malveillants) et les advisories retirés sont
ignorés ; une même faille publiée sous plusieurs identifiants (GHSA / GO /
PYSEC) n'est gardée qu'une fois, ses alias restant cherchables.

Tests : `CGO_ENABLED=1 go test -tags sqlite_fts5 ./...`

Dans la TUI : tape pour filtrer en direct, `↑`/`↓` pour naviguer, `tab` pour
passer de la liste au détail, `esc` (ou Ctrl-C) pour quitter.

La base est stockée dans `~/.config/vulnkb/vulnkb.db` (ou le dossier courant).

> Note réseau : la collecte contacte `cisa.gov` et
> `osv-vulnerabilities.storage.googleapis.com`, et `go mod tidy` récupère les
> modules. Si ton environnement filtre les sorties réseau (proxy/allowlist),
> autorise ces domaines et le proxy Go, ou utilise `GOPROXY=direct` pour tirer
> les dépendances GitHub.

## Architecture

```
internal/model/    format normalisé (Advisory) — le pivot commun
internal/store/    SQLite + index FTS5, upsert et recherche
internal/source/   interface Source + registre ; une source = un fichier
internal/tui/      interface terminal autonome (recherche / liste / détail)
main.go            CLI : sync, sources, tui
```

## Ajouter une source

Une source implémente l'interface `source.Source` (méthodes `Name()` et
`Fetch()`) et s'enregistre dans un `init()`. Voir `internal/source/cisakev.go`
comme modèle. Une source lourde peut implémenter `Optional()` pour être exclue
du sync par défaut (voir `osv.go`). Pistes : NVD (CVSS/CWE), flux RSS
d'éditeurs.

Pour les sources non structurées (articles de blog), l'étape suivante prévue
est un module `extract/` qui passe le texte à un LLM pour en tirer un
`Advisory` en JSON, rangé dans la même base.
