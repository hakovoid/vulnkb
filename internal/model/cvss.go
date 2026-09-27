package model

// CVSS est le score retenu pour un CVE dans la base NVD : il complète les
// entrées dont la source ne donne pas de sévérité (CISA KEV, CERT-FR…).
type CVSS struct {
	CVE     string
	Score   float64
	Level   int    // SevUnknown … SevCritical
	Version string // "3.1", "4.0", "2.0"…
	Vector  string
	Source  string // émetteur du score : nvd@nist.gov ou l'autorité du CVE
	CWE     string // faiblesses listées par NVD, ex. "CWE-79, CWE-80"
}

// ExploitRef pointe vers un exploit ou une preuve de concept publics pour un
// CVE : module Metasploit, entrée Exploit-DB, dépôt GitHub…
type ExploitRef struct {
	CVE   string
	Kind  string // "msf" (Metasploit), "edb" (Exploit-DB), "poc" (dépôt GitHub)
	Title string
	URL   string
	Stars int // popularité (dépôts PoC), 0 sinon
}
