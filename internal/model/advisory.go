// Package model définit le format normalisé d'une entrée de la base de
// connaissances. Toutes les sources (CVE, GHSA, articles de blog…) sont
// converties vers cette structure commune.
package model

import (
	"strings"
	"time"
)

// Advisory est l'unité de connaissance : une vulnérabilité ou un article
// technique, quelle que soit sa provenance.
type Advisory struct {
	// ID interne, unique et stable. Convention : "<source>:<externalID>".
	ID string

	// Source qui a produit l'entrée (ex. "cisa-kev", "osv", "blog").
	Source string

	// Identifiant d'origine : CVE-2026-1234, GHSA-xxxx, ou l'URL d'un article.
	ExternalID string

	Title   string
	Summary string

	// Composant / bibliothèque affecté (ex. "libheif").
	Component string

	// Type de faille (ex. "RCE", "SSRF", "heap overflow").
	VulnType string

	// Sévérité brute telle que fournie par la source (ex. "Critical", "9.8").
	Severity string

	AffectedVersions string
	FixedVersions    string

	// Action de remédiation recommandée par la source.
	Remediation string

	// Liens vers les sources originales (advisory, commit, article…).
	References []string

	Published time.Time // date de publication d'origine
	Fetched   time.Time // date de collecte par l'outil

	URL string // lien principal

	// Meilleur score NVD parmi les CVE de l'entrée (rempli à la lecture).
	NVD CVSS

	// Probabilité d'exploitation EPSS du CVE le plus menacé (0 à 1) et son
	// centile (rempli à la lecture).
	EPSS           float64
	EPSSPercentile float64

	// Exploited : un CVE de l'entrée figure au catalogue CISA KEV ;
	// HasExploit : un exploit ou une preuve de concept public existe
	// (remplis à la lecture).
	Exploited  bool
	HasExploit bool

	// Ranges : plages de versions vulnérables par paquet, sous forme
	// comparable (sources de paquets comme OSV). Sert au filtre « mes » quand
	// la liste de surveillance précise la version utilisée.
	Ranges []Range
}

// Range est une plage de versions vulnérables d'un paquet : à partir de
// Introduced (vide ou « 0 » : depuis toujours), jusqu'à Fixed exclue ou
// LastAffected incluse (les deux vides : pas encore corrigée).
type Range struct {
	Ecosystem    string // en minuscules : npm, pypi, go, crates.io, packagist, maven
	Package      string // nom normalisé (voir NormalizePackage)
	Introduced   string
	Fixed        string
	LastAffected string
}

// NormalizePackage met un nom de paquet sous la forme utilisée pour les
// comparaisons : minuscules, et pour PyPI « _ » et « . » équivalents à « - »
// (PEP 503 : Foo_Bar == foo-bar).
func NormalizePackage(ecosystem, name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if strings.EqualFold(ecosystem, "pypi") {
		name = strings.NewReplacer("_", "-", ".", "-").Replace(name)
	}
	return name
}
