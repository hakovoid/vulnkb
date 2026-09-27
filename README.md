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
./vulnkb sync            # collecte toutes les sources dans la base
./vulnkb sync cisa-kev   # collecte une source précise
./vulnkb                 # lance la TUI de recherche (commande par défaut)
```

Tests : `CGO_ENABLED=1 go test -tags sqlite_fts5 ./...`

Dans la TUI : tape pour filtrer en direct, `↑`/`↓` pour naviguer, `tab` pour
passer de la liste au détail, `esc` (ou Ctrl-C) pour quitter.

La base est stockée dans `~/.config/vulnkb/vulnkb.db` (ou le dossier courant).

> Note réseau : la source d'exemple télécharge le catalogue CISA KEV depuis
> `cisa.gov`, et `go mod tidy` récupère les modules. Si ton environnement
> filtre les sorties réseau (proxy/allowlist), autorise `cisa.gov` et le
> proxy Go, ou utilise `GOPROXY=direct` pour tirer les dépendances GitHub.

## Architecture

```
internal/model/    format normalisé (Advisory) — le pivot commun
internal/store/    SQLite + index FTS5, upsert et recherche
internal/source/   interface Source + registre ; une source = un fichier
internal/tui/      interface bubbletea (recherche / liste / détail)
main.go            CLI : sync, sources, tui
```

## Ajouter une source

Une source implémente l'interface `source.Source` (méthodes `Name()` et
`Fetch()`) et s'enregistre dans un `init()`. Voir `internal/source/cisakev.go`
comme modèle. Pistes de sources structurées à ajouter : NVD, OSV.dev, GitHub
Security Advisories, flux RSS d'éditeurs.

Pour les sources non structurées (articles de blog), l'étape suivante prévue
est un module `extract/` qui passe le texte à un LLM pour en tirer un
`Advisory` en JSON, rangé dans la même base.
