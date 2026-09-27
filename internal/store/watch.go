package store

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

// Liste de surveillance : produits ou mots-clés que l'utilisateur suit. Le
// filtre « mes » (voir Query) restreint la recherche aux entrées qui les
// mentionnent, pour ne voir que ce qui le concerne.
var (
	watchMu    sync.RWMutex
	watchTerms []string
)

// LoadWatchlist lit la liste de surveillance (un terme par ligne, « # » en
// commentaire, lignes vides ignorées) et la retient. Un fichier absent n'est
// pas une erreur : la liste est simplement vide.
func LoadWatchlist(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			SetWatchlist(nil)
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	var terms []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		terms = append(terms, line)
	}
	SetWatchlist(terms)
	return len(terms), sc.Err()
}

// SetWatchlist remplace la liste en mémoire (utile aux tests).
func SetWatchlist(terms []string) {
	watchMu.Lock()
	defer watchMu.Unlock()
	watchTerms = append([]string(nil), terms...)
}

// Watchlist renvoie une copie de la liste en mémoire.
func Watchlist() []string {
	watchMu.RLock()
	defer watchMu.RUnlock()
	return append([]string(nil), watchTerms...)
}
