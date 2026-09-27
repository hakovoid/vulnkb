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
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vulnkb/internal/exploits"
	"vulnkb/internal/extract"
	"vulnkb/internal/glossary"
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
	store.LoadWatchlist(watchlistPath())

	cmd := "tui"
	args := os.Args[1:]
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}

	switch cmd {
	case "sync":
		return sync(st, args)
	case "watch":
		return watchCmd(args)
	case "glossaire", "glossary", "glossaire.md":
		printGlossary()
		return nil
	case "info", "stats":
		return info(st)
	case "sources":
		for _, s := range source.All() {
			if source.IsOptional(s) {
				fmt.Printf("%s  (à la demande : vulnkb sync %s)\n", s.Name(), s.Name())
			} else {
				fmt.Println(s.Name())
			}
		}
		fmt.Println("nvd  (tous les CVE et leurs scores CVSS ; complète la sévérité des autres sources)")
		fmt.Println("exploits  (exploits et PoC publics : Exploit-DB, Metasploit, dépôts GitHub)")
		return nil
	case "add":
		return add(st, args)
	case "tui":
		return tui.Run(st)
	default:
		return fmt.Errorf("commande inconnue %q (sync | sources | add | watch | info | glossaire | tui)", cmd)
	}
}

// watchCmd gère la liste de surveillance : « watch » l'affiche, « watch add
// <termes…> » et « watch rm <termes…> » la modifient. Le filtre « mes » de la
// recherche s'y réfère.
func watchCmd(args []string) error {
	path := watchlistPath()
	terms := store.Watchlist()
	if len(args) == 0 {
		fmt.Printf("liste de surveillance (%s) :\n", path)
		if len(terms) == 0 {
			fmt.Println("  (vide) — ajoute un produit : vulnkb watch add nginx vtiger")
			return nil
		}
		for _, t := range terms {
			fmt.Println("  •", t)
		}
		fmt.Println("\nDans la recherche, le filtre « mes » ne montre que ces produits.")
		return nil
	}
	op, rest := args[0], args[1:]
	if (op != "add" && op != "rm") || len(rest) == 0 {
		return fmt.Errorf("usage : vulnkb watch [add|rm <termes…>]")
	}
	set := map[string]bool{}
	var out []string
	for _, t := range terms {
		set[strings.ToLower(t)] = true
		out = append(out, t)
	}
	for _, t := range rest {
		t = strings.TrimSpace(t)
		l := strings.ToLower(t)
		switch op {
		case "add":
			if t != "" && !set[l] {
				set[l] = true
				out = append(out, t)
			}
		case "rm":
			delete(set, l)
			kept := out[:0]
			for _, x := range out {
				if strings.ToLower(x) != l {
					kept = append(kept, x)
				}
			}
			out = kept
		}
	}
	if err := writeWatchlist(path, out); err != nil {
		return err
	}
	fmt.Printf("%d produit(s) surveillé(s) : %s\n", len(out), strings.Join(out, ", "))
	return nil
}

func writeWatchlist(path string, terms []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body := "# Produits surveillés par vulnkb (un par ligne). Filtre « mes » dans la recherche.\n"
	for _, t := range terms {
		body += t + "\n"
	}
	return os.WriteFile(path, []byte(body), 0o644)
}

// info affiche un aperçu de la base : taille, entrées par source, exploits,
// dernière collecte.
func info(st *store.Store) error {
	size, _ := st.DBSize()
	total, _ := st.Count()
	shown, _ := st.CountMatches("")
	bySrc, _ := st.CountsBySource()
	nvd, _ := st.CountNVD()
	expl, _ := st.CountExploits()
	last, _ := st.LastSync()

	fmt.Printf("Base   %s   (%s)\n", humanBytesCLI(size), dbPath())
	fmt.Printf("       %s entrées, dont %s affichées par défaut\n", groupInt(total), groupInt(shown))
	fmt.Println("\nEntrées par source :")
	for _, name := range []string{"nvd", "osv", "certfr", "cisa-kev", "article-ia"} {
		if n := bySrc[name]; n > 0 {
			fmt.Printf("  %-12s %s\n", name, groupInt(n))
		}
	}
	fmt.Printf("\nScores CVSS (NVD) : %s\n", groupInt(nvd))
	fmt.Printf("Exploits publics  : %s références\n", groupInt(expl))
	if last.IsZero() {
		fmt.Println("\nJamais synchronisé — lance : vulnkb sync")
	} else {
		fmt.Printf("\nDernière collecte : %s\n", last.Local().Format("2006-01-02 15:04"))
	}
	return nil
}

// humanBytesCLI met en forme une taille pour la ligne de commande.
func humanBytesCLI(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f Go", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%d Mo", n/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d Ko", n/(1<<10))
	default:
		return fmt.Sprintf("%d o", n)
	}
}

// groupInt sépare les milliers par une espace fine.
func groupInt(n int) string {
	s := strconv.Itoa(n)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// printGlossary affiche le glossaire complet des acronymes et notions.
func printGlossary() {
	fmt.Println("Glossaire vulnkb — acronymes et notions")
	for _, sec := range glossary.Sections() {
		fmt.Printf("\n\033[1m%s\033[0m\n", sec.Title)
		for _, t := range sec.Terms {
			fmt.Printf("  \033[36m%-16s\033[0m %s\n", t.Name, t.Def)
		}
	}
}

func watchlistPath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "vulnkb", "watch.txt")
	}
	return "vulnkb-watch.txt"
}

// add télécharge un article, en fait extraire une fiche par le LLM local,
// l'affiche puis l'enregistre après confirmation.
func add(st *store.Store, args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	modelName := fs.String("model", envOr("VULNKB_MODEL", "qwen2.5-coder:7b"), "modèle Ollama")
	host := fs.String("ollama", os.Getenv("OLLAMA_HOST"), "adresse d'Ollama (défaut http://localhost:11434)")
	yes := fs.Bool("y", false, "enregistrer sans demander confirmation")
	ref := fs.String("url", "", "pour un texte : URL d'origine (lien et identifiant de la fiche)")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage : vulnkb add [-y] [-model nom] [-ollama url] [-url origine] <url | fichier | ->")
		fmt.Fprintln(fs.Output(), "  <url>      page web à télécharger")
		fmt.Fprintln(fs.Output(), "  fichier    texte, Markdown ou HTML déjà enregistré")
		fmt.Fprintln(fs.Output(), "  -          texte lu sur l'entrée standard (copier-coller, pipe)")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("une URL, un fichier ou « - » attendu")
	}
	target := fs.Arg(0)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	var page extract.Page
	switch {
	case strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://"):
		fmt.Printf("→ téléchargement de %s… ", target)
		p, err := extract.Fetch(ctx, &http.Client{Timeout: 30 * time.Second}, target)
		if err != nil {
			fmt.Println()
			return err
		}
		page = p
	case target == "-":
		if isTerminal(os.Stdin) {
			fmt.Println("Colle le texte, puis Ctrl-D sur une ligne vide :")
		}
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		page = extract.FromText(string(b), *ref)
		fmt.Print("→ texte lu sur l'entrée standard… ")
	default:
		b, err := os.ReadFile(target)
		if err != nil {
			return fmt.Errorf("lecture de %s : %w", target, err)
		}
		page = extract.FromText(string(b), *ref)
		fmt.Printf("→ fichier %s… ", target)
	}
	if strings.TrimSpace(page.Text) == "" {
		fmt.Println()
		return fmt.Errorf("aucun texte à analyser")
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
	all := len(names) == 0
	withNVD, withExploits := all, all
	if !all {
		for _, n := range names {
			switch n {
			case "nvd":
				withNVD = true
			case "exploits", "exploit":
				withExploits = true
			default:
				s, ok := source.Get(n)
				if !ok {
					return fmt.Errorf("source inconnue: %s", n)
				}
				srcs = append(srcs, s)
			}
		}
	} else {
		srcs = source.Defaults()
	}

	for _, s := range srcs {
		fmt.Printf("→ %s… ", s.Name())
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		var (
			advs []model.Advisory
			err  error
		)
		if sf, ok := s.(source.Stateful); ok {
			var known map[string]time.Time
			if known, err = st.FetchedTimes(s.Name()); err == nil {
				advs, err = sf.FetchKnown(ctx, known)
			}
		} else {
			var since time.Time
			if source.IsIncremental(s) {
				since, _ = st.LastFetched(s.Name())
			}
			advs, err = s.Fetch(ctx, since)
		}
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
	if withExploits {
		syncExploits(st)
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

// syncExploits collecte les exploits publics (Exploit-DB, Metasploit, dépôts
// PoC) et remplace la table locale.
func syncExploits(st *store.Store) {
	fmt.Print("→ exploits publics… ")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	start := time.Now()
	refs, err := exploits.FetchAll(ctx, &http.Client{})
	if len(refs) == 0 && err != nil {
		fmt.Printf("échec : %v\n", err)
		return
	}
	if err != nil {
		fmt.Printf("(partiel : %v) ", err)
	}
	if e := st.ReplaceExploits(refs); e != nil {
		fmt.Printf("écriture : %v\n", e)
		return
	}
	total, _ := st.CountExploits()
	fmt.Printf("%d références en %s\n", total, time.Since(start).Round(time.Second))
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

// isTerminal indique si f est un terminal interactif (et non un pipe).
func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
