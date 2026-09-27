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
	"strconv"
	"strings"
	"time"

	"vulnkb/internal/extract"
	"vulnkb/internal/model"
	"vulnkb/internal/nvd"
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
		fmt.Println("nvd  (tous les CVE et leurs scores CVSS ; complète la sévérité des autres sources)")
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

// sync collecte les sources demandées (celles par défaut si aucune n'est
// nommée), puis les scores NVD.
func sync(st *store.Store, names []string) error {
	var srcs []source.Source
	withNVD := len(names) == 0
	if len(names) == 0 {
		srcs = source.Defaults()
	} else {
		for _, n := range names {
			if n == "nvd" {
				withNVD = true
				continue
			}
			s, ok := source.Get(n)
			if !ok {
				return fmt.Errorf("source inconnue: %s", n)
			}
			srcs = append(srcs, s)
		}
	}

	for _, s := range srcs {
		fmt.Printf("→ %s… ", s.Name())
		var since time.Time
		if source.IsIncremental(s) {
			since, _ = st.LastFetched(s.Name())
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		advs, err := s.Fetch(ctx, since)
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
	if withNVD {
		syncNVD(st)
	}
	fmt.Print("→ recoupements entre sources… ")
	if err := st.RefreshDerived(); err != nil {
		fmt.Printf("échec: %v\n", err)
	} else {
		fmt.Println("ok")
	}
	total, _ := st.Count()
	shown, _ := st.CountMatches("")
	fmt.Printf("base: %d entrées au total, dont %d affichées par défaut\n", total, shown)
	return nil
}

// nvdSyncedKey date la dernière synchro NVD complète ou incrémentale. Son nom
// change quand le contenu stocké change (ici : entrées en plus des scores),
// ce qui force une nouvelle synchro complète.
const nvdSyncedKey = "nvd_synced_entries"

// syncNVD met à jour les CVE et leurs scores CVSS : tous les flux annuels la
// première fois (ou si la dernière synchro date de plus de 7 jours), sinon
// seulement le flux des CVE modifiés sur les 8 derniers jours.
func syncNVD(st *store.Store) {
	fmt.Print("→ nvd (CVE et scores CVSS)… ")
	feeds := []string{"modified"}
	last, _ := st.Meta(nvdSyncedKey)
	t, err := time.Parse(time.RFC3339, last)
	if err != nil || time.Since(t) > 7*24*time.Hour || os.Getenv("VULNKB_NVD_FULL") != "" {
		feeds = nil
		for y := nvd.FirstYear; y <= time.Now().Year(); y++ {
			feeds = append(feeds, strconv.Itoa(y))
		}
		feeds = append(feeds, "modified")
		fmt.Print("synchro complète, ")
	}

	start := time.Now()
	entries, scores, failed := 0, 0, 0
	client := &http.Client{}
	for _, feed := range feeds {
		var advs []model.Advisory
		var cvss []model.CVSS
		var rejected []string
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		err := nvd.Fetch(ctx, client, nvd.FeedBase, feed, func(r nvd.Record) error {
			if r.Rejected {
				rejected = append(rejected, nvd.Source+":"+r.CVE)
				return nil
			}
			advs = append(advs, r.Advisory)
			if r.Score.CVE != "" {
				cvss = append(cvss, r.Score)
			}
			return nil
		})
		cancel()
		if err == nil {
			err = st.UpsertNVD(cvss)
		}
		if err == nil {
			_, err = st.Upsert(advs)
		}
		if err == nil {
			err = st.DeleteAdvisories(rejected)
		}
		if err != nil {
			failed++
			fmt.Printf("\n   %s : échec : %v\n   ", feed, err)
			continue
		}
		entries += len(advs)
		scores += len(cvss)
		if len(feeds) > 1 {
			fmt.Printf("%s ", feed)
		}
	}
	if failed == 0 {
		st.SetMeta(nvdSyncedKey, start.Format(time.RFC3339))
	}
	total, _ := st.CountNVD()
	fmt.Printf("\n   %d CVE et %d scores mis à jour en %s, %d CVE notés au total\n",
		entries, scores, time.Since(start).Round(time.Second), total)
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
