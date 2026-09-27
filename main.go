// vulnkb — base de connaissances de sécurité consultable en TUI.
//
// Sous-commandes :
//
//	vulnkb sync [source…]   collecte les entrées (toutes les sources par défaut)
//	vulnkb sources          liste les sources enregistrées
//	vulnkb tui              lance l'interface de recherche (défaut)
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	case "tui":
		return tui.Run(st)
	default:
		return fmt.Errorf("commande inconnue %q (sync | sources | tui)", cmd)
	}
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
