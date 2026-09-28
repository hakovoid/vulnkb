// Package glossary rassemble, en un seul endroit, la définition en français
// de tous les acronymes et notions rencontrés dans vulnkb. Il alimente à la
// fois la commande « vulnkb glossaire » et l'aide de l'interface (touche ?),
// pour que les deux restent cohérents.
package glossary

// Term est un acronyme ou une notion et sa définition.
type Term struct {
	Name string
	Def  string
}

// Section regroupe des termes par thème.
type Section struct {
	Title string
	Terms []Term
}

// Sections renvoie le glossaire complet, prêt à afficher.
func Sections() []Section {
	return []Section{
		{"Identifiants et bases", []Term{
			{"CVE", "Common Vulnerabilities and Exposures : identifiant universel d'une faille (CVE-AAAA-NNNN), attribué par le programme CVE (MITRE)."},
			{"GHSA", "GitHub Security Advisory : avis de la base de sécurité GitHub ; souvent doublé d'un CVE."},
			{"GO-…", "Go Vulnerability Database : avis propre à l'écosystème Go (pkg.go.dev/vuln)."},
			{"PYSEC", "Python Security advisories : base de failles des paquets Python (PyPI)."},
			{"RUSTSEC", "RustSec Advisory Database : base de failles de l'écosystème Rust (crates.io)."},
			{"BIT-…", "Bitnami : avis liés aux images et paquets Bitnami, repris par OSV."},
			{"OSV", "Open Source Vulnerabilities (osv.dev) : agrège les avis des écosystèmes open source (npm, PyPI, Go, RustSec, Packagist…)."},
			{"NVD", "National Vulnerability Database (NIST) : base de référence des CVE, avec description, produits, score CVSS et faiblesses."},
			{"KEV", "Known Exploited Vulnerabilities : catalogue CISA des failles vues exploitées dans la nature — à corriger en priorité."},
			{"CISA", "Cybersecurity and Infrastructure Security Agency : agence de cybersécurité des États-Unis."},
			{"CERT-FR", "Centre gouvernemental de veille, d'alerte et de réponse aux attaques informatiques, publie des avis et alertes en français."},
			{"ANSSI", "Agence nationale de la sécurité des systèmes d'information : l'autorité française dont dépend le CERT-FR."},
			{"CPE", "Common Platform Enumeration : identifiant normalisé d'un produit et d'une version (utilisé par NVD pour dire ce qui est affecté)."},
			{"CVE List", "Liste officielle des CVE (programme CVE, dépôt cvelistV5) : chaque fiche telle que publiée par son émetteur, avant l'analyse de NVD. Comble les fiches NVD encore vides (produits, versions, CWE)."},
			{"CNA", "CVE Numbering Authority : organisme habilité à attribuer des CVE (éditeur, CERT, GitHub, VulDB…) ; il décrit la faille à sa publication."},
			{"ADP", "Authorized Data Publisher : organisme qui complète les fiches CVE après publication, comme la CISA (Vulnrichment)."},
			{"Vulnrichment", "Enrichissement des CVE par la CISA : score CVSS, CWE et produits quand l'émetteur n'en donne pas, et évaluation SSVC."},
			{"BOD", "Binding Operational Directive : directive contraignante de la CISA (ex. BOD 22-01 impose de corriger les failles du catalogue KEV)."},
		}},
		{"Sévérité et scores", []Term{
			{"CVSS", "Common Vulnerability Scoring System : score de gravité de 0 à 10, calculé à partir d'un vecteur (vecteur d'attaque, complexité, impact…)."},
			{"CWE", "Common Weakness Enumeration : catégorie de faiblesse logicielle (ex. CWE-79 = injection de script / XSS)."},
			{"EPSS", "Exploit Prediction Scoring System (FIRST) : probabilité qu'un CVE soit exploité dans les 30 jours, recalculée chaque jour. Complète le CVSS : le CVSS mesure la gravité si la faille est exploitée, l'EPSS la probabilité qu'elle le soit. Filtre epss:10, tri par EPSS."},
			{"SSVC", "Stakeholder-Specific Vulnerability Categorization : évaluation de la CISA en trois critères — exploitation (aucune, preuve de concept publique, constatée), automatisable ou non, impact technique partiel ou total. Ligne « Éval. CISA » de la fiche ; une preuve de concept ou une exploitation constatée compte pour le filtre exploit."},
			{"PoC", "Proof of Concept : code ou démonstration prouvant qu'une faille est exploitable, sans forcément constituer une attaque complète."},
			{"0-day", "Faille exploitée avant qu'un correctif n'existe (« jour zéro »)."},
		}},
		{"Types de failles", []Term{
			{"RCE", "Remote Code Execution : exécution de code arbitraire à distance."},
			{"LPE", "Local Privilege Escalation : élévation de privilèges sur la machine locale."},
			{"XSS", "Cross-Site Scripting : injection de script dans une page vue par d'autres utilisateurs."},
			{"CSRF", "Cross-Site Request Forgery : action déclenchée à l'insu d'un utilisateur authentifié."},
			{"SSRF", "Server-Side Request Forgery : le serveur est amené à émettre des requêtes choisies par l'attaquant."},
			{"SQLi", "SQL Injection : requête SQL détournée via une entrée non filtrée."},
			{"XXE", "XML External Entity : lecture de fichiers ou SSRF via des entités XML externes."},
			{"SSTI", "Server-Side Template Injection : injection dans un moteur de gabarits, souvent vers une RCE."},
			{"IDOR", "Insecure Direct Object Reference : accès aux données d'autrui en modifiant un identifiant."},
			{"LFI / RFI", "Local / Remote File Inclusion : inclusion d'un fichier local ou distant contrôlé par l'attaquant."},
			{"DoS / DDoS", "Denial of Service (Distributed) : rendre un service indisponible, éventuellement depuis de multiples sources."},
			{"UAF", "Use After Free : accès à une zone mémoire déjà libérée (corruption mémoire)."},
			{"OOB", "Out Of Bounds : lecture ou écriture hors des limites d'un tampon."},
			{"TOCTOU", "Time-Of-Check to Time-Of-Use : condition de course entre une vérification et son utilisation."},
			{"ReDoS", "Regular expression Denial of Service : expression régulière dont le coût explose sur une entrée forgée."},
			{"Désérialisation", "Reconstruction d'objets depuis des données non fiables, menant souvent à une exécution de code."},
			{"Path traversal", "Accès à des fichiers hors du dossier prévu, via des séquences comme « ../ »."},
		}},
		{"Remédiation et menace", []Term{
			{"Correctif / patch", "Mise à jour qui supprime la faille."},
			{"Backport", "Report d'un correctif sur une version antérieure (fréquent dans les paquets Debian, Red Hat…)."},
			{"Remédiation", "Action qui supprime ou réduit le risque : mise à jour, changement de configuration, contournement."},
			{"IOC", "Indicator Of Compromise : trace observable d'une attaque (adresse IP, empreinte de fichier, domaine…)."},
			{"TTP", "Tactics, Techniques and Procedures : façons de faire d'un attaquant, souvent décrites via MITRE ATT&CK."},
			{"C2", "Command and Control : serveur par lequel un attaquant pilote une machine compromise."},
		}},
		{"Outils et exploits", []Term{
			{"Exploit-DB", "Base publique d'exploits et de preuves de concept (exploit-db.com)."},
			{"Metasploit", "Cadre d'exploitation ; un « module » automatise l'exploitation d'une faille."},
			{"PoC-in-GitHub", "Index de dépôts GitHub proposant des preuves de concept, classés par CVE."},
			{"JNDI", "Java Naming and Directory Interface : mécanisme Java détourné dans Log4Shell (CVE-2021-44228)."},
			{"SSO", "Single Sign-On : authentification unique partagée entre plusieurs services."},
		}},
		{"Dans vulnkb", []Term{
			{"TUI", "Text User Interface : interface en mode texte, dans le terminal."},
			{"FTS5", "Full-Text Search v5 : moteur de recherche plein-texte de SQLite, utilisé pour la recherche."},
			{"Source", "Origine d'une entrée : KEV, OSV, CERT-FR, NVD, ou IA (fiche extraite d'un article)."},
			{"Que faire", "Bloc en tête de fiche résumant la priorité et l'action concrète à mener."},
		}},
	}
}
