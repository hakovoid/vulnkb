// Package model définit le format normalisé d'une entrée de la base de
// connaissances. Toutes les sources (CVE, GHSA, articles de blog…) sont
// converties vers cette structure commune.
package model

import "time"

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
}
