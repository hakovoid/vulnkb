package store

import (
	"database/sql"
	"strings"
	"time"

	"vulnkb/internal/euvd"
)

// euvdSchema : identifiants de la base européenne EUVD (ENISA) et marqueur
// « exploitée » de l'ENISA, par CVE.
const euvdSchema = `
CREATE TABLE IF NOT EXISTS euvd (
    id              TEXT NOT NULL,
    cve             TEXT NOT NULL,
    exploited_since INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (id, cve)
);
CREATE INDEX IF NOT EXISTS euvd_cve ON euvd(cve);
`

// UpsertEUVD enregistre des fiches EUVD. Le marqueur « exploitée » n'est
// jamais effacé par une fiche qui ne le porte pas (les collectes par date de
// mise à jour ne le demandent pas) : seule ReplaceEUVDExploited le retire.
func (s *Store) UpsertEUVD(recs []euvd.Record) error {
	return s.inTx(func(tx *sql.Tx) error {
		stmt, err := tx.Prepare(`INSERT INTO euvd (id, cve, exploited_since) VALUES (?,?,?)
ON CONFLICT(id, cve) DO UPDATE SET exploited_since = MAX(exploited_since, excluded.exploited_since)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, r := range recs {
			for _, c := range r.CVEs {
				if _, err := stmt.Exec(r.ID, c, unix(r.ExploitedSince)); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ReplaceEUVDExploited aligne le marqueur « exploitée » sur la liste complète
// de l'ENISA : les fiches qui en sont sorties le perdent.
func (s *Store) ReplaceEUVDExploited(recs []euvd.Record) error {
	if err := s.UpsertEUVD(recs); err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, r := range recs {
		keep[r.ID] = true
	}
	return s.inTx(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT DISTINCT id FROM euvd WHERE exploited_since > 0`)
		if err != nil {
			return err
		}
		var drop []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			if !keep[id] {
				drop = append(drop, id)
			}
		}
		rows.Close()
		for _, id := range drop {
			if _, err := tx.Exec(`UPDATE euvd SET exploited_since = 0 WHERE id = ?`, id); err != nil {
				return err
			}
		}
		return rows.Err()
	})
}

// EUVDRef est l'identifiant EUVD d'un CVE et le marqueur de l'ENISA.
type EUVDRef struct {
	ID             string
	ExploitedSince time.Time
}

// EUVDFor renvoie les fiches EUVD liées à des CVE.
func (s *Store) EUVDFor(cves []string) ([]EUVDRef, error) {
	if len(cves) == 0 {
		return nil, nil
	}
	args := make([]any, len(cves))
	for i, c := range cves {
		args[i] = c
	}
	rows, err := s.db.Query(`SELECT id, MAX(exploited_since) FROM euvd WHERE cve IN (`+placeholders(len(cves))+`)
GROUP BY id ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EUVDRef
	for rows.Next() {
		var r EUVDRef
		var since int64
		if err := rows.Scan(&r.ID, &since); err != nil {
			return nil, err
		}
		r.ExploitedSince = fromUnix(since)
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountEUVD renvoie le nombre d'identifiants EUVD connus et de failles
// signalées exploitées par l'ENISA.
func (s *Store) CountEUVD() (ids, exploited int, err error) {
	err = s.db.QueryRow(`SELECT COUNT(DISTINCT id), COUNT(DISTINCT CASE WHEN exploited_since > 0 THEN id END) FROM euvd`).Scan(&ids, &exploited)
	return
}

// resolveEUVD remplace, dans le texte d'une recherche, les identifiants EUVD
// connus par leurs CVE : « EUVD-2026-72027 » trouve la fiche du CVE.
func (s *Store) resolveEUVD(q Query) Query {
	if !strings.Contains(strings.ToUpper(q.Text), "EUVD-") {
		return q
	}
	words := strings.Fields(q.Text)
	for i, w := range words {
		if !euvd.IsID(w) {
			continue
		}
		var cve string
		if s.db.QueryRow(`SELECT cve FROM euvd WHERE id = ? LIMIT 1`, strings.ToUpper(w)).Scan(&cve) == nil {
			words[i] = cve
		}
	}
	q.Text = strings.Join(words, " ")
	return q
}
