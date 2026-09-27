package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vulnkb/internal/manifest"
	"vulnkb/internal/store"
)

const watchHeader = "# Produits surveillés par vulnkb (un par ligne). Filtre « mes » dans la recherche.\n" +
	"# Terme simple (nginx) : cherché dans l'identifiant, le titre et le composant.\n" +
	"# Terme qualifié (npm:express, pypi:fastapi, go:github.com/x/y) : paquet exact de cet écosystème."

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

	lines := readWatchFile(path)
	known := map[string]bool{}
	for _, t := range termsOf(lines) {
		known[strings.ToLower(t)] = true
	}
	added, npm := 0, false
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
			continue
		}
		header := false
		for _, f := range found {
			var fresh []string
			for _, t := range f.Terms {
				if !known[strings.ToLower(t)] {
					known[strings.ToLower(t)] = true
					fresh = append(fresh, t)
				}
			}
			fmt.Printf("  %-48s %3d dépendance(s), %d nouvelle(s)\n", f.File, len(f.Terms), len(fresh))
			if len(fresh) == 0 {
				continue
			}
			for _, t := range fresh {
				npm = npm || strings.HasPrefix(t, "npm:")
			}
			if !header {
				lines = append(lines, "", fmt.Sprintf("# --- import du %s depuis %s ---", time.Now().Format("2006-01-02"), abs))
				header = true
			}
			lines, _ = appendTerms(lines, fresh, "# "+f.File)
			added += len(fresh)
		}
	}

	switch {
	case added == 0:
		fmt.Println("Rien de nouveau à ajouter.")
		return nil
	case *dry:
		fmt.Printf("%d terme(s) seraient ajoutés (simulation, liste inchangée).\n", added)
		return nil
	}
	if err := writeWatchFile(path, lines); err != nil {
		return err
	}
	fmt.Printf("%d terme(s) ajoutés à %s (total : %d).\n", added, path, len(termsOf(lines)))
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
	known := map[string]bool{}
	for _, t := range termsOf(lines) {
		known[strings.ToLower(t)] = true
	}
	var fresh []string
	for _, t := range terms {
		t = strings.TrimSpace(t)
		if t != "" && !known[strings.ToLower(t)] {
			known[strings.ToLower(t)] = true
			fresh = append(fresh, t)
		}
	}
	if len(fresh) == 0 {
		return lines, 0
	}
	if comment != "" {
		lines = append(lines, comment)
	}
	return append(lines, fresh...), len(fresh)
}

// removeTerms retire les lignes égales (sans tenir compte de la casse) aux
// termes donnés ; les commentaires restent.
func removeTerms(lines, terms []string) []string {
	drop := map[string]bool{}
	for _, t := range terms {
		drop[strings.ToLower(strings.TrimSpace(t))] = true
	}
	var out []string
	for _, l := range lines {
		if drop[strings.ToLower(strings.TrimSpace(l))] {
			continue
		}
		out = append(out, l)
	}
	return out
}

func watchlistPath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "vulnkb", "watch.txt")
	}
	return "vulnkb-watch.txt"
}
