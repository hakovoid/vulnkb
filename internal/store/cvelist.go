package store

import (
	"database/sql"
	"fmt"

	"vulnkb/internal/cvelist"
)

// cvelistSchema : données de la liste officielle des CVE (voir le paquet
// cvelist). cna_records ne garde que les CVE dont la fiche NVD est
// incomplète ; ssvc garde toutes les évaluations de la CISA.
const cvelistSchema = `
CREATE TABLE IF NOT EXISTS cna_records (
    cve       TEXT PRIMARY KEY,
    title     TEXT,
    component TEXT,
    affected  TEXT,
    fixed     TEXT,
    cwe       TEXT,
    score     REAL NOT NULL DEFAULT 0,
    level     INTEGER NOT NULL DEFAULT 0,
    version   TEXT,
    vector    TEXT,
    source    TEXT
);
CREATE TABLE IF NOT EXISTS ssvc (
    cve          TEXT PRIMARY KEY,
    exploitation TEXT,
    automatable  TEXT,
    impact       TEXT
);
`

// CVEListFilter renvoie une fonction qui dit si les données d'un CVE sont
// utiles : fiche NVD absente, ou sans produit, sans CWE ou sans score, ou CVE
// déjà suivi (pour garder ses données à jour). Les CVE entièrement analysés
// par NVD n'ont pas besoin d'être stockés.
func (s *Store) CVEListFilter() (func(cve string) bool, error) {
	rows, err := s.db.Query(`
SELECT a.external_id,
       IFNULL(a.component, '') <> '' AND IFNULL(a.vuln_type, '') <> ''
         AND EXISTS (SELECT 1 FROM nvd_scores n WHERE n.cve = a.external_id)
         AND NOT EXISTS (SELECT 1 FROM cna_records r WHERE r.cve = a.external_id)
FROM advisories a WHERE a.source = 'nvd'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	complete := map[string]bool{}
	for rows.Next() {
		var cve string
		var ok bool
		if err := rows.Scan(&cve, &ok); err != nil {
			return nil, err
		}
		complete[cve] = ok
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return func(cve string) bool { return !complete[cve] }, nil
}

// UpsertCVEList enregistre un lot de fiches. wanted choisit celles dont les
// données descriptives sont gardées (voir CVEListFilter) ; les évaluations
// SSVC le sont toujours. Un CVE rejeté est retiré des deux tables.
func (s *Store) UpsertCVEList(recs []cvelist.Record, wanted func(string) bool) (kept int, err error) {
	err = s.inTx(func(tx *sql.Tx) error {
		rec, err := tx.Prepare(`INSERT OR REPLACE INTO cna_records
  (cve, title, component, affected, fixed, cwe, score, level, version, vector, source)
  VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer rec.Close()
		ss, err := tx.Prepare(`INSERT OR REPLACE INTO ssvc (cve, exploitation, automatable, impact) VALUES (?,?,?,?)`)
		if err != nil {
			return err
		}
		defer ss.Close()
		for _, r := range recs {
			if r.Rejected {
				for _, t := range []string{"cna_records", "ssvc"} {
					if _, err := tx.Exec(`DELETE FROM `+t+` WHERE cve = ?`, r.CVE); err != nil {
						return err
					}
				}
				continue
			}
			if r.SSVC.Exploitation != "" {
				if _, err := ss.Exec(r.CVE, r.SSVC.Exploitation, r.SSVC.Automatable, r.SSVC.Impact); err != nil {
					return fmt.Errorf("SSVC %s: %w", r.CVE, err)
				}
			}
			if wanted != nil && !wanted(r.CVE) {
				continue
			}
			c := r.Score
			if _, err := rec.Exec(r.CVE, r.Title, r.Component, r.Affected, r.Fixed, r.CWE,
				c.Score, c.Level, c.Version, c.Vector, c.Source); err != nil {
				return fmt.Errorf("CVE %s: %w", r.CVE, err)
			}
			kept++
		}
		return nil
	})
	return kept, err
}

// ApplyCVEList comble les trous des fiches NVD avec les données de la liste
// officielle : titre de l'émetteur, produits, versions, CWE, et un score quand
// NVD n'en a pas. Ce que NVD fournit n'est jamais remplacé (sauf le titre,
// que NVD ne donne pas : il est tiré de la description). À appeler après
// chaque synchro NVD ou cvelist, qui réécrivent les fiches.
func (s *Store) ApplyCVEList() error {
	_, err := s.db.Exec(`
INSERT OR IGNORE INTO nvd_scores (cve, score, level, version, vector, source, cwe)
  SELECT cve, score, level, version, vector, source, cwe FROM cna_records WHERE score > 0;
UPDATE advisories SET
  title = CASE WHEN c.title <> '' THEN c.title ELSE advisories.title END,
  component = CASE WHEN IFNULL(advisories.component, '') = '' THEN c.component ELSE advisories.component END,
  affected_versions = CASE WHEN IFNULL(advisories.affected_versions, '') = '' THEN c.affected ELSE advisories.affected_versions END,
  fixed_versions = CASE WHEN IFNULL(advisories.fixed_versions, '') = '' THEN c.fixed ELSE advisories.fixed_versions END,
  vuln_type = CASE WHEN IFNULL(advisories.vuln_type, '') = '' THEN c.cwe ELSE advisories.vuln_type END
FROM cna_records c
WHERE advisories.id = 'nvd:' || c.cve AND (
     (c.title <> '' AND advisories.title <> c.title)
  OR (IFNULL(advisories.component, '') = '' AND c.component <> '')
  OR (IFNULL(advisories.affected_versions, '') = '' AND c.affected <> '')
  OR (IFNULL(advisories.fixed_versions, '') = '' AND c.fixed <> '')
  OR (IFNULL(advisories.vuln_type, '') = '' AND c.cwe <> ''));`)
	return err
}

// CountCVEList renvoie le nombre de fiches gardées et d'évaluations SSVC.
func (s *Store) CountCVEList() (records, ssvc int, err error) {
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM cna_records`).Scan(&records); err != nil {
		return
	}
	err = s.db.QueryRow(`SELECT COUNT(*) FROM ssvc`).Scan(&ssvc)
	return
}

// ssvcRank ordonne les niveaux d'exploitation, du plus grave au moins grave.
var ssvcRank = map[string]int{"active": 0, "poc": 1, "none": 2}

// SSVCFor renvoie l'évaluation SSVC la plus grave parmi des CVE (zéro si
// aucune).
func (s *Store) SSVCFor(cves []string) (cvelist.SSVC, error) {
	var best cvelist.SSVC
	if len(cves) == 0 {
		return best, nil
	}
	args := make([]any, len(cves))
	for i, c := range cves {
		args[i] = c
	}
	rows, err := s.db.Query(`SELECT exploitation, automatable, impact FROM ssvc WHERE cve IN (`+placeholders(len(cves))+`)`, args...)
	if err != nil {
		return best, err
	}
	defer rows.Close()
	for rows.Next() {
		var v cvelist.SSVC
		if err := rows.Scan(&v.Exploitation, &v.Automatable, &v.Impact); err != nil {
			return best, err
		}
		r, ok := ssvcRank[v.Exploitation]
		if !ok {
			continue
		}
		if br, bok := ssvcRank[best.Exploitation]; !bok || r < br ||
			(r == br && v.Impact == "total" && best.Impact != "total") {
			best = v
		}
	}
	return best, rows.Err()
}
