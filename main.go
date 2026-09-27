// vulnkb — base de connaissances de sécurité consultable en TUI.
//
// Sous-commandes :
//
//	vulnkb sync [source…]   collecte les entrées (toutes les sources par défaut)
//	vulnkb sources          liste les sources enregistrées
//	vulnkb add [-y] <url>   extrait une fiche d'un article via Ollama
//	vulnkb tui              lance l'interface de recherche (défaut)
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vulnkb/internal/extract"
	"vulnkb/internal/model"
	"vulnkb/internal/source"
	"vulnkb/internal/store"
	"vulnkb/internal/tui"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "erreur:", err)
		os.Exit(1)
	}
}

func run() error {
	dbPath := dbPath()
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	cmd := "tui"
	args := os.Args[1:]
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}

	switch cmd {
	case "sync":
		return sync(st, args)
	case "sources":
		for _, s := range source.All() {
			if source.IsOptional(s) {
				fmt.Printf("%s  (à la demande : vulnkb sync %s)\n", s.Name(), s.Name())
			} else {
				fmt.Println(s.Name())
			}
		}
		return nil
	case "add":
		return add(st, args)
	case "tui":
		return tui.Run(st)
	default:
		return fmt.Errorf("commande inconnue %q (sync | sources | add | tui)", cmd)
	}
}

// add télécharge un article, en fait extraire une fiche par le LLM local,
// l'affiche puis l'enregistre après confirmation.
func add(st *store.Store, args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	modelName := fs.String("model", envOr("VULNKB_MODEL", "qwen2.5-coder:7b"), "modèle Ollama")
	host := fs.String("ollama", os.Getenv("OLLAMA_HOST"), "adresse d'Ollama (défaut http://localhost:11434)")
	yes := fs.Bool("y", false, "enregistrer sans demander confirmation")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage : vulnkb add [-y] [-model nom] [-ollama url] <url>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("une URL attendue")
	}
	pageURL := fs.Arg(0)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	fmt.Printf("→ téléchargement de %s… ", pageURL)
	page, err := extract.Fetch(ctx, &http.Client{Timeout: 30 * time.Second}, pageURL)
	if err != nil {
		fmt.Println()
		return err
	}
	fmt.Printf("%d caractères\n", len([]rune(page.Text)))

	llm := &extract.Ollama{Host: extract.NormalizeHost(*host), Model: *modelName, NumCtx: extract.ContextFor(page.Text), Client: http.DefaultClient}
	fmt.Printf("→ extraction avec %s (peut prendre quelques minutes sans GPU)… ", *modelName)
	start := time.Now()
	adv, err := extract.Extract(ctx, llm, page)
	if err != nil {
		fmt.Println()
		return err
	}
	fmt.Printf("%s\n\n", time.Since(start).Round(time.Second))

	printAdvisory(adv)

	if !*yes && !confirm("\nEnregistrer cette fiche ? [o/N] ") {
		fmt.Println("non enregistrée")
		return nil
	}
	if _, err := st.Upsert([]model.Advisory{adv}); err != nil {
		return err
	}
	fmt.Println("enregistrée (source " + extract.Source + ")")
	return nil
}

func printAdvisory(a model.Advisory) {
	row := func(label, val string) {
		if strings.TrimSpace(val) != "" {
			fmt.Printf("%-19s %s\n", label+" :", val)
		}
	}
	row("Titre", a.Title)
	row("ID", a.ExternalID)
	row("Composant", a.Component)
	row("Type", a.VulnType)
	row("Sévérité", a.Severity)
	row("Versions affectées", a.AffectedVersions)
	row("Corrigé dans", a.FixedVersions)
	if !a.Published.IsZero() {
		row("Publié", a.Published.Format("2006-01-02"))
	}
	row("Résumé", a.Summary)
	row("Remédiation", a.Remediation)
	if len(a.References) > 0 {
		fmt.Println("Références :")
		for _, r := range a.References {
			fmt.Println("  •", r)
		}
	}
}

func confirm(prompt string) bool {
	fmt.Print(prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "o", "oui", "y", "yes":
		return true
	}
	return false
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// sync collecte les sources demandées (celles par défaut si aucune n'est nommée).
func sync(st *store.Store, names []string) error {
	var srcs []source.Source
	if len(names) == 0 {
		srcs = source.Defaults()
	} else {
		for _, n := range names {
			s, ok := source.Get(n)
			if !ok {
				return fmt.Errorf("source inconnue: %s", n)
			}
			srcs = append(srcs, s)
		}
	}

	for _, s := range srcs {
		fmt.Printf("→ %s… ", s.Name())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		advs, err := s.Fetch(ctx, time.Time{})
		cancel()
		if err != nil {
			fmt.Printf("échec: %v\n", err)
			continue
		}
		n, err := st.Upsert(advs)
		if err != nil {
			fmt.Printf("écriture: %v\n", err)
			continue
		}
		fmt.Printf("%d entrées\n", n)
	}
	total, _ := st.Count()
	fmt.Printf("base: %d entrées au total\n", total)
	return nil
}

// dbPath place la base dans le répertoire de config utilisateur, ou dans le
// répertoire courant en secours.
func dbPath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		d := filepath.Join(dir, "vulnkb")
		if os.MkdirAll(d, 0o755) == nil {
			return filepath.Join(d, "vulnkb.db")
		}
	}
	return "vulnkb.db"
}
