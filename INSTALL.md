# Guide d'installation et d'utilisation — vulnkb

`vulnkb` est une base de connaissances de sécurité consultable en terminal.
Elle collecte des advisories de vulnérabilités depuis des sources publiques,
les range dans une base SQLite avec recherche plein-texte, et te permet de
retrouver une info en quelques frappes.

---

## 1. Prérequis

- **Go 1.23+** — `go version` pour vérifier. Sinon : https://go.dev/dl/
- **Un compilateur C** (gcc ou clang). La base s'appuie sur `go-sqlite3`, qui
  utilise cgo.
  - macOS : `xcode-select --install`
  - Debian/Ubuntu : `sudo apt install build-essential`
  - Fedora : `sudo dnf install gcc`
- **Accès réseau** vers GitHub (dépendances) et vers les sources de données
  (`cisa.gov` et `osv-vulnerabilities.storage.googleapis.com`).

---

## 2. Installation

Depuis le dossier du projet :

```sh
go mod tidy                                          # récupère les dépendances (une fois)
CGO_ENABLED=1 go build -tags sqlite_fts5 -o vulnkb . # compile
```

> Le tag `sqlite_fts5` est **obligatoire** : c'est lui qui active la recherche
> plein-texte. Sans lui, la base refusera de créer son index.

Tu obtiens un binaire autonome `vulnkb`. Pour l'avoir partout :

```sh
sudo mv vulnkb /usr/local/bin/     # ou : cp vulnkb ~/.local/bin/
```

Vérifier que tout roule :

```sh
CGO_ENABLED=1 go test -tags sqlite_fts5 ./...   # doit afficher "ok"
```

### Si le réseau est filtré (proxy / allowlist d'entreprise)

- Pour les dépendances Go, tirer directement depuis GitHub :
  ```sh
  GOPROXY=direct GOSUMDB=off go mod tidy
  ```
- Pour la collecte, autorise `cisa.gov` et
  `osv-vulnerabilities.storage.googleapis.com` en sortie, ou ajoute une source
  interne à ton réseau (voir §5).

---

## 3. Premier lancement

```sh
./vulnkb sources     # liste les sources disponibles
./vulnkb sync        # remplit la base depuis les sources par défaut
./vulnkb             # ouvre l'interface de recherche
```

Sources disponibles :

- `cisa-kev` : CVE activement exploitées (catalogue CISA KEV).
- `osv-go`, `osv-pypi`, `osv-packagist`, `osv-crates`, `osv-maven` : advisories
  OSV.dev, avec versions affectées, version corrective, CWE et liens.
- `osv-npm` : **à la demande** (export d'environ 200 Mo), à lancer avec
  `./vulnkb sync osv-npm`.

Ordre de grandeur : un `sync` complet prend une dizaine de secondes sur une
bonne connexion, pour environ 29 000 entrées (36 000 avec npm) et une base de
100 à 120 Mo.

`sync` affiche le nombre d'entrées récupérées par source et le total en base.
À relancer quand tu veux rafraîchir (l'insertion est idempotente : pas de
doublons, les entrées existantes sont mises à jour).

La base est stockée dans `~/.config/vulnkb/vulnkb.db` (ou dans le dossier
courant si le dossier de config n'est pas accessible). Pour repartir de zéro,
supprime ce fichier.

---

## 4. Utiliser la TUI

Lance `./vulnkb` (ou `./vulnkb tui`).

| Touche        | Action                                        |
|---------------|-----------------------------------------------|
| *(taper)*     | filtre les résultats en direct                |
| `Backspace`   | efface un caractère de la recherche           |
| `↑` / `↓`     | naviguer dans la liste (ou faire défiler le détail) |
| `Tab`         | basculer le focus entre la liste et le détail |
| `Esc` / `Ctrl-C` | quitter                                    |

La recherche porte sur l'identifiant (CVE, GHSA… et leurs alias), le titre, le
résumé, le composant et le type de faille (CWE pour OSV). Exemples de
requêtes : `libheif`, `RCE`, `CVE-2026`, `deserialization`, `CWE-79`,
`golang.org/x/net`. Une recherche vide affiche les entrées les plus
récentes.

Commandes en ligne (hors TUI) :

```sh
./vulnkb sync            # collecte les sources par défaut
./vulnkb sync osv-npm    # collecte une source précise
./vulnkb sources         # liste les sources enregistrées
./vulnkb add <url>       # ajoute un article via Ollama (voir ci-dessous)
./vulnkb tui             # interface de recherche (= ./vulnkb sans argument)
```

### Ajouter un article (extraction IA)

Pour un write-up ou un billet de blog qui n'existe dans aucune source
structurée, `add` fait extraire une fiche par le LLM local.

Prérequis : l'Ollama partagé doit tourner, avec le modèle voulu.

```sh
cd ~/kuro_apps/ollama && docker compose up -d
docker exec ollama-shared ollama pull qwen2.5-coder:7b   # si absent
```

Utilisation :

```sh
./vulnkb add https://www.hacktron.ai/blog/hacking-openai
./vulnkb add -y <url>                          # sans confirmation
./vulnkb add -model qwen2.5-coder:14b <url>    # autre modèle
```

La fiche est affichée avant d'être enregistrée. Elle apparaît ensuite dans la
TUI avec la source `article-ia`, pour rappeler qu'elle vient d'un modèle et
doit être relue. Les CVE, GHSA et numéros de version absents de l'article
sont retirés automatiquement ; le résumé et la sévérité ne sont pas vérifiés.

Durée indicative sans GPU (Ryzen 7 5800U, article de 14 000 caractères) :
environ 3 à 4 minutes avec `qwen2.5-coder:7b`, 7 à 8 minutes avec le 14b.

| Réglage | Option | Variable | Défaut |
|---------|--------|----------|--------|
| Modèle | `-model` | `VULNKB_MODEL` | `qwen2.5-coder:7b` |
| Adresse d'Ollama | `-ollama` | `OLLAMA_HOST` | `http://localhost:11434` |

---

## 5. Ajouter une source

Une source est un petit fichier dans `internal/source/` qui implémente
l'interface `Source` (`Name()` et `Fetch()`) et s'enregistre dans un `init()`.
Le modèle à copier est `internal/source/cisakev.go`.

Squelette :

```go
func init() { Register(&maSource{}) }

type maSource struct{}

func (s *maSource) Name() string { return "ma-source" }

func (s *maSource) Fetch(ctx context.Context, since time.Time) ([]model.Advisory, error) {
    // 1. récupérer les données (API, RSS, fichier…)
    // 2. les convertir en []model.Advisory
    // 3. renvoyer
}
```

Recompile, et la source apparaît automatiquement dans `vulnkb sources` et est
collectée par `vulnkb sync`. Si elle est lourde, ajoute une méthode
`Optional() bool` qui renvoie `true` : elle ne sera collectée que si on la
nomme (`vulnkb sync ma-source`). Pistes : NVD (CVSS/CWE), flux RSS d'éditeurs.

---

## 6. Dépannage

| Symptôme | Cause probable | Solution |
|----------|----------------|----------|
| `no such module fts5` / erreur à la création de la base | tag de build oublié | recompiler avec `-tags sqlite_fts5` |
| erreur cgo / `gcc: command not found` | pas de compilateur C | installer build-essential / Xcode CLT |
| `403 Forbidden` sur `go mod tidy` | proxy Go bloqué | `GOPROXY=direct GOSUMDB=off go mod tidy` |
| `sync` échoue en `Forbidden` | `cisa.gov` ou le bucket OSV bloqué en sortie | autoriser le domaine, ou ajouter une source interne |
| `add` : « Ollama injoignable » | Ollama arrêté | `cd ~/kuro_apps/ollama && docker compose up -d` |
| `add` : `model "…" not found` | modèle non téléchargé | `docker exec ollama-shared ollama pull <modèle>` |
| `add` : fiche en anglais ou incomplète | modèle trop petit | réessayer avec `-model qwen2.5-coder:14b` |
| l'affichage TUI est bancal | terminal trop étroit / non-TTY | élargir la fenêtre, lancer dans un vrai terminal |
