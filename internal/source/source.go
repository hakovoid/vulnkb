// Package source définit le contrat commun à toutes les sources de données
// et tient un registre des sources disponibles. Ajouter une source consiste
// à écrire un type qui implémente Source, puis à l'enregistrer via Register.
package source

import (
	"context"
	"sort"
	"sync"
	"time"

	"vulnkb/internal/model"
)

// Source est le contrat que toute origine de connaissances doit remplir :
// CVE structurées, advisories, ou extraction d'articles de blog.
type Source interface {
	// Name est l'identifiant court et unique de la source (ex. "cisa-kev").
	Name() string

	// Fetch récupère les entrées publiées depuis `since` (zéro = tout),
	// déjà normalisées au format model.Advisory.
	Fetch(ctx context.Context, since time.Time) ([]model.Advisory, error)
}

// Optional est implémentée par les sources trop lourdes pour être collectées
// par défaut : elles ne sont synchronisées que si on les nomme explicitement.
type Optional interface {
	Optional() bool
}

// IsOptional indique si la source est exclue du sync par défaut.
func IsOptional(s Source) bool {
	o, ok := s.(Optional)
	return ok && o.Optional()
}

// Defaults renvoie les sources collectées par un sync sans argument.
func Defaults() []Source {
	var out []Source
	for _, s := range All() {
		if !IsOptional(s) {
			out = append(out, s)
		}
	}
	return out
}

var (
	mu       sync.RWMutex
	registry = map[string]Source{}
)

// Register ajoute une source au registre global. Appelé typiquement depuis
// un init() dans le fichier de chaque source.
func Register(s Source) {
	mu.Lock()
	defer mu.Unlock()
	registry[s.Name()] = s
}

// Get renvoie une source par son nom.
func Get(name string) (Source, bool) {
	mu.RLock()
	defer mu.RUnlock()
	s, ok := registry[name]
	return s, ok
}

// All renvoie toutes les sources enregistrées, triées par nom.
func All() []Source {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Source, 0, len(registry))
	for _, s := range registry {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Names renvoie les noms des sources enregistrées, triés.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
