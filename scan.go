package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"vulnkb/internal/manifest"
	"vulnkb/internal/model"
	"vulnkb/internal/store"
	"vulnkb/internal/tui"
	"vulnkb/internal/versions"
)

// errFindings signale que l'analyse a trouvé des failles au-dessus du seuil
// -fail : main sort alors avec le code 2 (0 = rien, 1 = erreur), pour les
// hooks git et l'intégration continue.
var errFindings = errors.New("failles trouvées")

// vulnHit est une faille qui touche une dépendance analysée.
type vulnHit struct {
	Adv     model.Advisory
	Level   int
	Fixed   string // version corrective pour la version utilisée, "" si inconnue
	NoRange bool   // pas de plage de versions : gardée par prudence
}

// pkgResult est une dépendance vulnérable et ses failles.
type pkgResult struct {
	Term    store.WatchTerm
	Vulns   []vulnHit
	Target  string // version à viser : le plus haut des correctifs
	Unfixed bool   // au moins une faille sans correctif connu
}

// fileResult est le bilan d'un fichier de dépendances.
type fileResult struct {
	File       string
	Vulnerable []pkgResult
	Clean      int
	Unknown    []string // paquets sans version certaine
	Images     []string // images Docker (pas de version vérifiable)
}

type scanOptions struct {
	Dev, Indirect bool
	Min           int // sévérité minimale retenue
}

// levelOf est la sévérité effective d'une entrée : celle de la source, ou à
// défaut le score NVD de ses CVE.
func levelOf(a model.Advisory) int {
	if l := model.ParseSeverity(a.Severity).Level; l > 0 {
		return l
	}
	return a.NVD.Level
}

// scanRoot analyse les fichiers de dépendances sous root. Seules les
// dépendances de version connue sont vérifiées ; les autres sont listées.
func scanRoot(st *store.Store, root string, opt scanOptions) ([]fileResult, error) {
	found, err := manifest.Scan(root, manifest.Options{Dev: opt.Dev, Indirect: opt.Indirect})
	if err != nil {
		return nil, err
	}
	var out []fileResult
	for _, f := range found {
		fr := fileResult{File: f.File}
		for _, t := range f.Terms {
			wt := store.ParseWatchTerm(t)
			switch {
			case wt.Ecosystem == "":
				fr.Images = append(fr.Images, wt.Name)
				continue
			case wt.Versions == "":
				fr.Unknown = append(fr.Unknown, wt.Name)
				continue
			}
			advs, err := st.SearchWithWatch([]string{t}, "", store.SortSeverity, 1000)
			if err != nil {
				return nil, err
			}
			pr := pkgResult{Term: wt}
			for _, a := range advs {
				h := vulnHit{Adv: a, Level: levelOf(a)}
				if h.Level < opt.Min {
					continue
				}
				hits, err := st.VersionHits(a.ID, []string{t})
				if err != nil {
					return nil, err
				}
				if len(hits) == 0 {
					h.NoRange = true
				} else {
					h.Fixed = hits[0].Fixed
				}
				if h.Fixed == "" {
					pr.Unfixed = true
				} else if c, ok := versions.Compare(h.Fixed, pr.Target); pr.Target == "" || (ok && c > 0) {
					pr.Target = h.Fixed
				}
				pr.Vulns = append(pr.Vulns, h)
			}
			if len(pr.Vulns) == 0 {
				fr.Clean++
				continue
			}
			sort.SliceStable(pr.Vulns, func(i, j int) bool {
				a, b := pr.Vulns[i], pr.Vulns[j]
				if a.Level != b.Level {
					return a.Level > b.Level
				}
				if a.Adv.Exploited != b.Adv.Exploited {
					return a.Adv.Exploited
				}
				return a.Adv.HasExploit && !b.Adv.HasExploit
			})
			fr.Vulnerable = append(fr.Vulnerable, pr)
		}
		sort.SliceStable(fr.Vulnerable, func(i, j int) bool {
			return fr.Vulnerable[i].Vulns[0].Level > fr.Vulnerable[j].Vulns[0].Level
		})
		out = append(out, fr)
	}
	return out, nil
}

var levelNames = [...]string{"inconnue", "faible", "moyenne", "élevée", "critique"}

// parseLevel lit un seuil de sévérité : crit/critique, high/elevee,
// med/moyenne, low/faible, all/tout.
func parseLevel(s string) (int, error) {
	switch fold := strings.NewReplacer("é", "e", "è", "e").Replace(strings.ToLower(strings.TrimSpace(s))); fold {
	case "all", "tout", "toutes", "inconnue", "0":
		return model.SevUnknown, nil
	case "low", "faible":
		return model.SevLow, nil
	case "med", "medium", "moyenne":
		return model.SevMedium, nil
	case "high", "elevee", "haute":
		return model.SevHigh, nil
	case "crit", "critical", "critique":
		return model.SevCritical, nil
	case "none", "aucun", "jamais":
		return model.SevCritical + 1, nil
	}
	return 0, fmt.Errorf("sévérité inconnue %q (crit, high, med, low, all)", s)
}

// scanCmd : vulnkb scan [options] [dossiers…]
func scanCmd(st *store.Store, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	verbose := fs.Bool("v", false, "lister toutes les failles de chaque dépendance (sinon les 5 plus graves)")
	minS := fs.String("min", "all", "sévérité minimale affichée : crit, high, med, low, all")
	failS := fs.String("fail", "high", "code de sortie 2 si une faille atteint cette sévérité : crit, high, med, low, all, none")
	dev := fs.Bool("dev", false, "inclure les dépendances de développement")
	indirect := fs.Bool("indirect", false, "inclure les dépendances indirectes de go.mod")
	html := fs.Bool("html", false, "écrire aussi un rapport HTML des failles trouvées")
	out := fs.String("o", "", "fichier du rapport HTML (implique -html)")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage : vulnkb scan [options] [dossiers…]  (défaut : dossier courant)")
		fmt.Fprintln(fs.Output(), "  Analyse les dépendances des projets (versions des fichiers de verrouillage) et")
		fmt.Fprintln(fs.Output(), "  liste les failles qui touchent les versions utilisées. Code de sortie : 0 rien,")
		fmt.Fprintln(fs.Output(), "  2 failles au-dessus du seuil -fail, 1 erreur.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	minL, err := parseLevel(*minS)
	if err != nil {
		return err
	}
	failL, err := parseLevel(*failS)
	if err != nil {
		return err
	}
	roots := fs.Args()
	if len(roots) == 0 {
		roots = []string{"."}
	}
	color := isTerminal(os.Stdout)
	c := func(code, s string) string {
		if !color {
			return s
		}
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}
	sevColor := [...]string{"2", "32", "33", "31", "1;31"}

	var all []model.Advisory
	seen := map[string]bool{}
	var bySev [5]int
	checked, vulnerable, exploited, overFail := 0, 0, 0, 0
	ecos := map[string]bool{}
	for _, root := range roots {
		abs, err := filepath.Abs(root)
		if err != nil {
			return err
		}
		files, err := scanRoot(st, abs, scanOptions{Dev: *dev, Indirect: *indirect, Min: minL})
		if err != nil {
			return fmt.Errorf("analyse de %s : %w", root, err)
		}
		fmt.Println(c("1", "Analyse de "+abs))
		if len(files) == 0 {
			fmt.Println("  aucun fichier de dépendances trouvé")
		}
		for _, f := range files {
			fmt.Println()
			fmt.Println(c("1;36", f.File))
			for _, p := range f.Vulnerable {
				vulnerable++
				checked++
				ecos[p.Term.Label] = true
				var counts [5]int
				expl, pub := false, false
				for _, v := range p.Vulns {
					counts[v.Level]++
					expl = expl || v.Adv.Exploited
					pub = pub || v.Adv.HasExploit
					if !seen[v.Adv.ID] {
						seen[v.Adv.ID] = true
						all = append(all, v.Adv)
						bySev[v.Level]++
						if v.Adv.Exploited {
							exploited++
						}
					}
					if v.Level >= failL {
						overFail++
					}
				}
				var parts []string
				for l := model.SevCritical; l >= 0; l-- {
					if counts[l] > 0 {
						parts = append(parts, c(sevColor[l], fmt.Sprintf("%d %s", counts[l], plural(levelNames[l], counts[l]))))
					}
				}
				line := fmt.Sprintf("  %s %s %s %s — %d %s (%s)", c("1;31", "✗"), p.Term.Label, c("1", p.Term.Name),
					strings.ReplaceAll(p.Term.Versions, ",", ", "), len(p.Vulns), plural("faille", len(p.Vulns)), strings.Join(parts, ", "))
				if expl {
					line += " · " + c("1;31", "● exploitée")
				} else if pub {
					line += " · " + c("35", "exploit public")
				}
				fmt.Println(line)
				switch {
				case p.Target != "" && p.Unfixed:
					fmt.Println("      " + c("32", "↑ mettre à jour en "+p.Target+" ou plus") + c("2", " (certaines failles n'ont pas de correctif connu)"))
				case p.Target != "":
					fmt.Println("      " + c("32", "↑ mettre à jour en "+p.Target+" ou plus"))
				default:
					fmt.Println("      " + c("2", "pas de version corrective connue — voir les fiches"))
				}
				shown := p.Vulns
				if !*verbose && len(shown) > 5 {
					shown = shown[:5]
				}
				for _, v := range shown {
					id := strings.Fields(v.Adv.ExternalID + " ")[0]
					if cves := store.CVEs(v.Adv.ExternalID); len(cves) > 0 {
						id = cves[0]
					}
					title := []rune(strings.Join(strings.Fields(v.Adv.Title), " "))
					if len(title) > 62 {
						title = append(title[:61], '…')
					}
					fix := ""
					switch {
					case v.NoRange:
						fix = c("2", "  plage de versions inconnue")
					case v.Fixed != "":
						fix = c("2", "  corrigé en "+v.Fixed)
					}
					mark := " "
					if v.Adv.Exploited {
						mark = c("1;31", "●")
					}
					fmt.Printf("      %s %-8s %-16s %s%s\n", mark, c(sevColor[v.Level], levelNames[v.Level]), id, string(title), fix)
				}
				if len(shown) < len(p.Vulns) {
					fmt.Println(c("2", fmt.Sprintf("        … et %d autres (-v pour tout voir)", len(p.Vulns)-len(shown))))
				}
			}
			checked += f.Clean
			if f.Clean > 0 {
				what := "sans faille connue"
				if minL > model.SevUnknown {
					what = "sans faille " + levelNames[minL] + " ou plus"
				}
				fmt.Printf("  %s %d %s %s\n", c("32", "✓"), f.Clean, plural("dépendance", f.Clean), what)
			}
			if len(f.Unknown) > 0 {
				fmt.Printf("  %s %d sans version certaine, non vérifiées : %s\n", c("33", "?"), len(f.Unknown),
					c("2", strings.Join(f.Unknown, ", ")))
			}
			if len(f.Images) > 0 {
				fmt.Printf("  %s %d %s non vérifiées : %s\n", c("2", "·"), len(f.Images), plural("image Docker", len(f.Images)),
					c("2", strings.Join(f.Images, ", ")))
			}
		}
		fmt.Println()
	}

	// bilan
	var parts []string
	for l := model.SevCritical; l >= 0; l-- {
		if bySev[l] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", bySev[l], plural(levelNames[l], bySev[l])))
		}
	}
	if len(all) == 0 {
		fmt.Printf("%s aucune faille connue sur %d %s vérifiées.\n", c("1;32", "Bilan :"), checked, plural("dépendance", checked))
	} else {
		fmt.Printf("%s %d %s vulnérables sur %d vérifiées · %d %s (%s)", c("1", "Bilan :"), vulnerable,
			plural("dépendance", vulnerable), checked, len(all), plural("faille", len(all)), strings.Join(parts, ", "))
		if exploited > 0 {
			fmt.Printf(" · %s", c("1;31", fmt.Sprintf("%d %s", exploited, plural("exploitée", exploited))))
		}
		fmt.Println()
	}
	if ecos["npm"] && !st.HasEcosystem("npm") {
		fmt.Println(c("33", "Attention : aucune faille npm en base — lance « vulnkb sync osv-npm » pour vérifier les paquets npm."))
	}
	if *html || *out != "" {
		if len(all) == 0 {
			fmt.Println("Pas de rapport HTML : aucune faille à exporter.")
		} else {
			sort.SliceStable(all, func(i, j int) bool { return levelOf(all[i]) > levelOf(all[j]) })
			title := "Analyse de " + strings.Join(roots, ", ")
			path, err := tui.ExportList(st, all, title, *out)
			if err != nil {
				return err
			}
			fmt.Println("Rapport HTML :", path)
		}
	}
	if overFail > 0 {
		return errFindings
	}
	return nil
}

// plural accorde un mot simple (« faille » → « failles »).
func plural(word string, n int) string {
	if n > 1 && !strings.HasSuffix(word, "s") {
		if i := strings.IndexByte(word, ' '); i > 0 { // « image Docker » → « images Docker »
			return word[:i] + "s" + word[i:]
		}
		return word + "s"
	}
	return word
}
