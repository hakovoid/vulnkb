package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"vulnkb/internal/manifest"
	"vulnkb/internal/store"
)

const watchHeader = "# Produits surveillés par vulnkb (un par ligne). Filtre « mes » dans la recherche.\n" +
	"# Terme simple (nginx) : cherché dans l'identifiant, le titre et le composant.\n" +
	"# Terme qualifié (npm:express, pypi:fastapi, go:github.com/x/y) : paquet exact de cet écosystème.\n" +
	"# Avec version (npm:express@4.18.2, ou 4.18.2,5.0.1) : seulement les failles qui la touchent."

// watchCmd gère la liste de surveillance :
//
//	vulnkb watch                     affiche la liste
//	vulnkb watch add <termes…>       ajoute des termes
//	vulnkb watch rm <termes…>        retire des termes
//	vulnkb watch import [dossiers…]  ajoute les dépendances des projets trouvés
//
// Le fichier est édité ligne par ligne : les commentaires sont conservés.
func watchCmd(args []string) error {
	path := watchlistPath()
	if len(args) == 0 {
		return showWatchlist(path)
	}
	switch op, rest := args[0], args[1:]; op {
	case "add", "rm":
		if len(rest) == 0 {
			return fmt.Errorf("usage : vulnkb watch %s <termes…>", op)
		}
		lines := readWatchFile(path)
		if op == "add" {
			lines, _ = appendTerms(lines, rest, "")
		} else {
			lines = removeTerms(lines, rest)
		}
		if err := writeWatchFile(path, lines); err != nil {
			return err
		}
		fmt.Printf("%d terme(s) surveillé(s)\n", len(termsOf(lines)))
		return nil
	case "import":
		return watchImport(path, rest)
	default:
		return fmt.Errorf("usage : vulnkb watch [add|rm <termes…> | import [dossiers…]]")
	}
}

func showWatchlist(path string) error {
	lines := readWatchFile(path)
	terms := termsOf(lines)
	fmt.Printf("Liste de surveillance : %d terme(s)  (%s)\n", len(terms), path)
	if len(terms) == 0 {
		fmt.Println("  vide — ajoute un produit (vulnkb watch add nginx vtiger)")
		fmt.Println("  ou importe les dépendances de tes projets (vulnkb watch import ~/projets)")
		return nil
	}
	for _, l := range lines {
		t := strings.TrimSpace(l)
		switch {
		case t == "" || strings.HasPrefix(t, "# Produits") || strings.HasPrefix(t, "# Terme"):
		case strings.HasPrefix(t, "#"):
			fmt.Printf("\n\033[2m%s\033[0m\n", strings.TrimSpace(strings.TrimPrefix(t, "#")))
		default:
			fmt.Println("  •", t)
		}
	}
	fmt.Println("\nDans la recherche, le filtre « mes » (ou Ctrl-T) ne montre que ces produits.")
	return nil
}

// watchImport lit les fichiers de dépendances sous chaque dossier et ajoute
// à la liste les termes qu'elle ne contient pas encore, regroupés par fichier.
func watchImport(path string, args []string) error {
	fs := flag.NewFlagSet("watch import", flag.ContinueOnError)
	dev := fs.Bool("dev", false, "inclure les dépendances de développement (devDependencies…)")
	indirect := fs.Bool("indirect", false, "inclure les dépendances indirectes de go.mod")
	dry := fs.Bool("n", false, "afficher ce qui serait ajouté, sans modifier la liste")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage : vulnkb watch import [-dev] [-indirect] [-n] [dossiers…]  (défaut : dossier courant)")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	roots := fs.Args()
	if len(roots) == 0 {
		roots = []string{"."}
	}

	// 1. lecture de tous les projets : les versions d'un même paquet sont
	// réunies ; une seule version incertaine (plage « ^1.2 », pas de fichier
	// de verrouillage) et le terme reste sans version, par prudence
	type fileFound struct {
		abs   string
		found manifest.Found
	}
	var files []fileFound
	vers := map[string][]string{}
	uncertain := map[string]bool{}
	for _, root := range roots {
		abs, err := filepath.Abs(root)
		if err != nil {
			return err
		}
		found, err := manifest.Scan(abs, manifest.Options{Dev: *dev, Indirect: *indirect})
		if err != nil {
			return fmt.Errorf("exploration de %s : %w", root, err)
		}
		if len(found) == 0 {
			fmt.Printf("%s : aucun fichier de dépendances trouvé\n", abs)
		}
		for _, f := range found {
			files = append(files, fileFound{abs, f})
			for _, t := range f.Terms {
				wt := store.ParseWatchTerm(t)
				k := watchKey(wt)
				if wt.Ecosystem == "" {
					continue
				}
				if wt.Versions == "" {
					uncertain[k] = true
				}
				for _, v := range strings.Split(wt.Versions, ",") {
					if v != "" && !slices.Contains(vers[k], v) {
						vers[k] = append(vers[k], v)
					}
				}
			}
		}
	}
	final := func(wt store.WatchTerm) string {
		k := watchKey(wt)
		base := wt.Ecosystem + ":" + wt.Name
		if wt.Ecosystem == "" {
			return wt.Name
		}
		if uncertain[k] || len(vers[k]) == 0 {
			return base
		}
		return base + "@" + strings.Join(vers[k], ",")
	}

	// 2. mise à jour des versions des termes déjà suivis
	lines := readWatchFile(path)
	known := map[string]bool{}
	updated := 0
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		wt := store.ParseWatchTerm(t)
		k := watchKey(wt)
		known[k] = true
		if wt.Ecosystem == "" || (!uncertain[k] && len(vers[k]) == 0) {
			continue // paquet absent de cet import : inchangé
		}
		if nl := final(wt); nl != t {
			lines[i] = nl
			updated++
			fmt.Printf("  version : %s → %s\n", t, nl)
		}
	}

	// 3. ajout des nouveaux termes, regroupés par fichier
	added, npm := 0, false
	lastRoot := ""
	for _, ff := range files {
		f := ff.found
		var fresh []string
		for _, t := range f.Terms {
			wt := store.ParseWatchTerm(t)
			if k := watchKey(wt); !known[k] {
				known[k] = true
				fresh = append(fresh, final(wt))
			}
		}
		fmt.Printf("  %-48s %3d dépendance(s), %d nouvelle(s)\n", f.File, len(f.Terms), len(fresh))
		if len(fresh) == 0 {
			continue
		}
		for _, t := range fresh {
			npm = npm || strings.HasPrefix(t, "npm:")
		}
		if ff.abs != lastRoot {
			lines = append(lines, "", fmt.Sprintf("# --- import du %s depuis %s ---", time.Now().Format("2006-01-02"), ff.abs))
			lastRoot = ff.abs
		}
		lines, _ = appendTerms(lines, fresh, "# "+f.File)
		added += len(fresh)
	}

	switch {
	case added == 0 && updated == 0:
		fmt.Println("Rien de nouveau à ajouter.")
		return nil
	case *dry:
		fmt.Printf("%d terme(s) seraient ajoutés et %d version(s) mises à jour (simulation, liste inchangée).\n", added, updated)
		return nil
	}
	if err := writeWatchFile(path, lines); err != nil {
		return err
	}
	fmt.Printf("%d terme(s) ajoutés et %d version(s) mises à jour dans %s (total : %d).\n", added, updated, path, len(termsOf(lines)))
	if npm {
		fmt.Println("Des paquets npm sont surveillés : pense à collecter leurs failles avec « vulnkb sync osv-npm ».")
	}
	return nil
}

// readWatchFile renvoie les lignes du fichier, avec l'en-tête s'il est absent.
func readWatchFile(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil || len(strings.TrimSpace(string(b))) == 0 {
		return strings.Split(watchHeader, "\n")
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func writeWatchFile(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	_, err := store.LoadWatchlist(path)
	return err
}

// termsOf renvoie les termes (lignes hors commentaires et lignes vides).
func termsOf(lines []string) []string {
	var out []string
	for _, l := range lines {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
			out = append(out, t)
		}
	}
	return out
}

// appendTerms ajoute les termes absents de la liste, précédés d'un
// commentaire s'il est fourni ; renvoie aussi le nombre ajouté.
func appendTerms(lines, terms []string, comment string) ([]string, int) {
	known := map[string]int{} // clé → indice de la ligne
	for i, l := range lines {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
			known[watchKey(store.ParseWatchTerm(t))] = i
		}
	}
	var fresh []string
	for _, t := range terms {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		wt := store.ParseWatchTerm(t)
		k := watchKey(wt)
		if i, ok := known[k]; ok {
			if i >= 0 && wt.Ecosystem != "" {
				lines[i] = t // même paquet, autre version : remplacée
			}
			continue
		}
		known[k] = -1
		fresh = append(fresh, t)
	}
	if len(fresh) == 0 {
		return lines, 0
	}
	if comment != "" {
		lines = append(lines, comment)
	}
	return append(lines, fresh...), len(fresh)
}

// removeTerms retire les termes donnés, quelle que soit leur version
// (« npm:axios » retire « npm:axios@1.6.0 ») ; les commentaires restent.
func removeTerms(lines, terms []string) []string {
	drop := map[string]bool{}
	for _, t := range terms {
		drop[watchKey(store.ParseWatchTerm(strings.TrimSpace(t)))] = true
	}
	var out []string
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t != "" && !strings.HasPrefix(t, "#") && drop[watchKey(store.ParseWatchTerm(t))] {
			continue
		}
		out = append(out, l)
	}
	return out
}

// watchKey identifie un terme sans sa version : « npm:axios@1.6.0 » et
// « npm:Axios » désignent le même paquet.
func watchKey(t store.WatchTerm) string {
	if t.Ecosystem != "" {
		return t.Ecosystem + ":" + t.Package
	}
	return strings.ToLower(t.Name)
}

func watchlistPath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "vulnkb", "watch.txt")
	}
	return "vulnkb-watch.txt"
}
