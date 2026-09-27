# Guide d'installation et d'utilisation — vulnkb

`vulnkb` est une base de connaissances de sécurité consultable en terminal.
Elle collecte des advisories de vulnérabilités depuis des sources publiques,
les range dans une base SQLite avec recherche plein-texte, et te permet de
retrouver une info en quelques frappes.

---

## 1. Prérequis

- **Go 1.25+** — `go version` pour vérifier. Sinon : https://go.dev/dl/
- **Un compilateur C** (gcc ou clang). La base s'appuie sur `go-sqlite3`, qui
  utilise cgo.
  - macOS : `xcode-select --install`
  - Debian/Ubuntu : `sudo apt install build-essential`
  - Fedora : `sudo dnf install gcc`
- **Accès réseau** vers GitHub (dépendances) et vers les sources de données
  (`cisa.gov`, `osv-vulnerabilities.storage.googleapis.com`,
  `www.cert.ssi.gouv.fr` et `nvd.nist.gov`).

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
- Pour la collecte, autorise `cisa.gov`,
  `osv-vulnerabilities.storage.googleapis.com`, `www.cert.ssi.gouv.fr` et
  `nvd.nist.gov` en sortie, ou ajoute une source
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
- `certfr` : avis et alertes du CERT-FR, en français, sur les 3 dernières
  années par défaut (environ 3 800 bulletins). Les synchros suivantes ne
  récupèrent que les bulletins nouveaux ou révisés depuis. La profondeur se
  règle avec `VULNKB_CERTFR_DAYS` (jours) : l'élargir, par exemple
  `VULNKB_CERTFR_DAYS=1825 ./vulnkb sync certfr` pour 5 ans, déclenche le
  rattrapage des bulletins plus anciens à la synchro suivante, sans
  re-télécharger ceux déjà en base.
- `nvd` : la base NVD (NIST), soit tous les CVE publiés (environ 387 000),
  y compris pour les logiciels hors registres de paquets (vtiger, appliances,
  OS…). Chaque CVE devient une entrée : description, produits et plages de
  versions (CPE), CWE, score CVSS, références. Les scores servent aussi de
  sévérité aux entrées qui n'en ont pas (CISA KEV, CERT-FR). Un CVE déjà
  décrit par OSV, CISA KEV ou un article n'apparaît pas en double : son entrée
  NVD est masquée, sauf avec `src:nvd`. La première synchro télécharge les
  flux annuels (environ 220 Mo, 1 min 30) ; les suivantes, si elles ont lieu
  dans les 7 jours, seulement le flux des 8 derniers jours (quelques
  secondes). Pour forcer une synchro complète :
  `VULNKB_NVD_FULL=1 ./vulnkb sync nvd`.
- `exploits` : signale les CVE pour lesquels un exploit ou une preuve de
  concept public existe, depuis Exploit-DB, les modules Metasploit et l'index
  PoC-in-GitHub (~50 000 références, quelques secondes). Ce ne sont que des
  métadonnées (titre, lien, popularité), pas du code d'attaque : elles servent
  à prioriser. Dans la TUI, le filtre `exploit` isole ces entrées et la fiche
  liste les liens ; combinable, par exemple `mes exploit sev:high+`.

- `epss` : probabilité EPSS, publiée chaque jour par le FIRST, qu'un CVE
  soit exploité dans les 30 jours (~380 000 CVE, une dizaine de secondes).
  Le CVSS dit la gravité si la faille est exploitée, l'EPSS la probabilité
  qu'elle le soit. Une fiche prend le score de son CVE le plus menacé ; elle
  l'affiche avec son centile, « Que faire » signale une probabilité d'au moins
  10 %, et la liste se trie par EPSS (`Alt-O`, colonne dédiée) ou se filtre
  (`epss:10`). Combinaison utile : `mes epss:10`.

Ordre de grandeur : un premier `sync` complet prend environ 2 minutes sur une
bonne connexion, pour environ 410 000 entrées (dont 384 000 affichées) et une
base d'environ 1 Go, dont 800 Mo pour NVD.

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
| `PgUp` / `PgDn` | page précédente / suivante (liste ou détail) |
| `Début` / `Fin` | premier / dernier résultat                 |
| `Alt-G` / `Ctrl-G` | aller au résultat n° … (taper le numéro, puis `Entrée`) |
| `Tab`         | basculer le focus entre la liste et le détail |
| `Alt-T` / `Ctrl-T` | activer / couper le filtre `mes` (produits surveillés) |
| `Alt-O` / `Ctrl-O` | changer le tri : pertinence → date → criticité → EPSS |
| `Alt-Y` / `Ctrl-Y` | changer le thème de couleurs (mémorisé) |
| `Alt-S`       | liste des sources : contenu, nombre d'entrées, dernière collecte |
| `Alt-I`       | statistiques : sévérités, années, menaces, CWE, exposition de tes produits |
| `Alt-E`       | exporter la fiche affichée en HTML |
| `Alt-R`       | exporter en HTML tous les résultats de la recherche (rapport) |
| `Alt-M`       | rendre la souris au terminal (clic sur les liens, sélection de texte), et inversement |
| `Alt-←` / `Alt-→` | rétrécir / élargir le panneau liste (aussi `Ctrl`, ou glisser la séparation à la souris) |
| molette       | faire défiler la liste ou le détail selon le panneau survolé |
| `Entrée`      | ouvrir la fiche en plein écran (`Entrée` ou `Esc` pour revenir) |
| `?`           | aide : légende des couleurs et glossaire (CVE, GHSA, CWE, CVSS…) |
| `Esc` / `Ctrl-C` | quitter (`Esc` ferme d'abord l'aide)       |

Chaque raccourci `Ctrl` a son équivalent `Alt`, à utiliser quand le terminal
garde le `Ctrl` pour lui (VS Code intercepte par exemple `Ctrl-G`).

Les liens de la fiche (références, correctif, exploits, URL des résumés) sont
cliquables, sur une seule ligne, même raccourcis par « … » : le terminal reçoit
l'adresse complète (norme OSC 8, gérée par VS Code, GNOME Terminal, Kitty,
WezTerm, iTerm2…). Selon le terminal, le clic demande `Ctrl` (VS Code) ; si
l'application capte la souris et que le clic ne passe pas, `Alt-M` la rend au
terminal, ou lance `VULNKB_MOUSE=0 vulnkb`.

Chaque ligne de la liste montre, de gauche à droite : un `●` rouge si la
faille est exploitée activement (son CVE figure au catalogue CISA KEV), la
sévérité en couleur (`CRIT`, `HIGH`, `MED`, `LOW`), la source (`KEV`, `OSV`,
`FR`, `IA`), l'identifiant et le titre. Quand une source ne fournit qu'un
vecteur CVSS 3.x, le score est calculé et affiché dans le détail. Le détail
donne aussi le nom en clair des CWE courantes.

En tête de fiche, un bloc **« Que faire »** synthétise l'essentiel : si la
faille est exploitée activement (priorité), l'action concrète (mettre à jour
vers la version corrective, ou la remédiation), et le lien le plus utile pour
corriger (avis éditeur ou correctif, en écartant les agrégateurs comme NVD).

L'interface suit le fond du terminal (thème sombre ou clair) et le nombre de
couleurs qu'il gère (16, 256 ou 16 millions). Six thèmes de couleurs sont proposés :
**bleu** (défaut), **rose**, **vert**, **cyan**, **violet** et **orange**. Ils changent
l'accent (badge, barre de recherche, panneau actif, touches), les identifiants
et libellés, et la ligne sélectionnée. `Ctrl-Y` passe au suivant dans
l'interface ; `vulnkb theme` les liste et `vulnkb theme rose` en choisit un.
Le choix est mémorisé ; `VULNKB_THEME=vert vulnkb` le force ponctuellement,
et `VULNKB_ACCENT=#d97757` remplace la seule couleur d'accent. Sur un terminal de moins de 100 colonnes, la
liste et la fiche s'empilent.

Les blocs de code des descriptions (PoC, extraits vulnérables, requêtes HTTP…)
sont colorés selon leur langage, avec une marge `│` ; le langage est deviné
quand la description ne l'indique pas. Le thème par défaut (`monokai`) convient
aux terminaux sombres ; pour un terminal clair : `VULNKB_CODE_STYLE=github
vulnkb` (autres thèmes : `dracula`, `nord`, `solarized-light`…).

La recherche porte sur l'identifiant (CVE, GHSA… et leurs alias), le titre, le
résumé, le composant, le type de faille (CWE pour OSV, risques pour le
CERT-FR), les versions affectées et corrigées, et la remédiation. Chaque mot
est un début de mot, plusieurs mots se cumulent, casse et accents sont
ignorés. Exemples : `libheif`, `RCE`, `CVE-2026`, `deserializ`, `CWE-79`,
`golang.org/x/net`, `1.27.1`.

Des filtres se combinent au texte :

| Filtre | Effet |
|--------|-------|
| `sev:crit` | sévérité critique (`crit`, `high`, `med`, `low`, `inconnue` ; ou `critique`, `elevee`, `moyenne`, `faible`) |
| `sev:crit,high` | plusieurs sévérités |
| `sev:high+` | cette sévérité ou plus grave |
| `src:kev` | une source (`kev`, `osv`, `fr`, `nvd`, `ia`) ; `src:kev,fr` pour plusieurs |
| `exploitee` | failles exploitées activement : CVE présent dans CISA KEV, toutes sources confondues |
| `exploit` | un exploit ou une preuve de concept public existe (Exploit-DB, Metasploit, GitHub) |
| `epss:10` | probabilité d'exploitation EPSS d'au moins 10 % (`epss:1`, `epss:50`…) |
| `mes` | seulement les produits de ta liste de surveillance (voir ci-dessous) |

Exemples : `nginx sev:high+ src:osv`, `exploitee src:fr`, `sev:crit gitea`,
`mes exploitee`.

### Liste de surveillance (filtre `mes`)

Tu peux suivre les produits qui te concernent (tes apps, tes dépendances) et
les retrouver d'un filtre :

```sh
vulnkb watch                         # affiche la liste et son fichier
vulnkb watch add nginx vtiger koai   # ajoute des produits (ou mots-clés)
vulnkb watch rm koai                 # en retire
vulnkb watch import ~/kuro_apps      # ajoute les dépendances de tous tes projets
vulnkb watch import -n ~/kuro_apps   # simulation : affiche sans rien modifier
```

`watch import` explore les dossiers donnés et lit les fichiers de dépendances :
`package.json` (npm), `go.mod`, `requirements.txt` et `pyproject.toml`
(Python), `composer.json` (PHP), `Cargo.toml` (Rust) et les images des
`docker-compose`. Il ignore `node_modules`, les sorties de compilation, les
dossiers cachés et les copies de sauvegarde (`…backup…`, `…-bck`). Les
dépendances de développement et les dépendances Go indirectes ne sont prises
qu'avec `-dev` et `-indirect`. Les nouveaux termes sont ajoutés au fichier,
regroupés par projet sous un commentaire ; relancer l'import n'ajoute que ce
qui a changé.

La liste est un simple fichier `~/.config/vulnkb/watch.txt` (un terme par
ligne, `#` pour commenter, éditable à la main). Deux sortes de termes :

- **terme simple** (`nginx`, `vtiger`, une image Docker) : cherché en début de
  mot dans l'identifiant, le titre et le composant ;
- **terme qualifié** (`npm:express`, `pypi:fastapi`, `go:github.com/spf13/cobra`,
  `packagist:…`, `crates:…`) : seul ce paquet exact de cet écosystème compte,
  pour éviter le bruit des noms courts (`npm:ms` ne ramène pas « MSRC »,
  `npm:react` ne ramène pas `@aws-amplify/codegen-ui-react`).

Dans la recherche, `mes` (ou **Ctrl-T**, qui l'ajoute et le retire) ne montre
que les entrées liées à ta liste ; `mes sev:high+` ou `mes exploitee`
combinent avec les autres filtres. Si tes projets utilisent npm, collecte
aussi `vulnkb sync osv-npm`, qui n'est pas dans le sync par défaut.
Les filtres reconnus s'affichent à droite de la saisie ; un filtre mal écrit
est signalé en rouge.

La sévérité filtrée est celle de la source ; à défaut (CISA KEV, CERT-FR), la
plus haute sévérité NVD des CVE de l'entrée. Un avis CERT-FR qui couvre
plusieurs CVE est donc classé selon le plus grave.

Une recherche vide affiche toutes les entrées, les plus récentes en premier.
L'en-tête indique la position (« résultat 1 234 / 30 559 ») ; tous les
résultats sont accessibles, pas seulement les premiers.

Commandes en ligne (hors TUI) :

```sh
./vulnkb sync            # collecte les sources par défaut
./vulnkb sync osv-npm    # collecte une source précise
./vulnkb sources         # liste les sources enregistrées
./vulnkb add <url>       # ajoute un article via Ollama (voir ci-dessous)
./vulnkb glossaire       # glossaire : tous les acronymes définis en français
./vulnkb info            # aperçu : taille de la base, entrées par source
./vulnkb stats           # statistiques détaillées + exposition par produit (Alt-I)
./vulnkb tui             # interface de recherche (= ./vulnkb sans argument)
```

### Exporter en HTML

Une fiche ou une recherche entière s'exporte dans un fichier HTML autonome,
lisible hors ligne dans n'importe quel navigateur, imprimable, et qui suit le
thème clair ou sombre du navigateur :

- dans l'interface : `Alt-E` exporte la fiche affichée, `Alt-R` tous les
  résultats de la recherche en cours, dans l'ordre du tri courant ;
- en ligne de commande, avec les mêmes filtres :

```sh
vulnkb export mes sev:high+                  # tes produits, sévérité élevée ou critique
vulnkb export -tri epss mes epss:10          # tes produits les plus menacés, triés par EPSS
vulnkb export -o ~/rapport.html exploitee src:fr   # fichier choisi
```

Le rapport commence par des compteurs (sévérités, exploitées, exploit
public, EPSS ≥ 10 %) et un sommaire, puis donne chaque fiche avec son bloc
« Que faire », ses scores, ses exploits publics, ses avis CERT-FR et ses
références cliquables. 1 000 fiches au plus ; les fichiers vont dans
`~/vulnkb-exports` (ou `VULNKB_EXPORT_DIR`). Le contenu des sources est
échappé : un texte piégé ne peut rien exécuter dans le navigateur.

### Ajouter un article ou un texte (extraction IA)

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
./vulnkb add ~/notes/faille.md                 # un fichier texte, Markdown ou HTML
./vulnkb add -url https://origine.example -    # un texte collé (Ctrl-D pour finir) ou pipé
./vulnkb add -y <url>                          # sans confirmation
./vulnkb add -model qwen2.5-coder:14b <url>    # autre modèle
```

Un texte (fichier ou entrée standard) est mis au format de la base comme une
page web : le modèle remplit la fiche à partir du contenu. `-url` indique
l'origine du texte ; sans elle, l'identifiant est calculé à partir du contenu.

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
| `sync` échoue en `Forbidden` | `cisa.gov`, le bucket OSV, le CERT-FR ou NVD bloqué en sortie | autoriser le domaine, ou ajouter une source interne |
| `add` : « Ollama injoignable » | Ollama arrêté | `cd ~/kuro_apps/ollama && docker compose up -d` |
| `add` : `model "…" not found` | modèle non téléchargé | `docker exec ollama-shared ollama pull <modèle>` |
| `add` : fiche en anglais ou incomplète | modèle trop petit | réessayer avec `-model qwen2.5-coder:14b` |
| l'affichage TUI est bancal | terminal trop étroit / non-TTY | élargir la fenêtre, lancer dans un vrai terminal |
