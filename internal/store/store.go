// Package store gère la persistance des advisories dans SQLite, avec un
// index de recherche plein-texte (FTS5) pour interroger rapidement.
package store

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"

	"vulnkb/internal/model"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

// Open ouvre (ou crée) la base au chemin donné et applique le schéma.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("ouverture db: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// migrate crée les tables si elles n'existent pas. La table FTS5 est tenue
// synchronisée avec la table principale via des triggers.
func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS advisories (
    id                TEXT PRIMARY KEY,
    source            TEXT NOT NULL,
    external_id       TEXT,
    title             TEXT,
    summary           TEXT,
    component         TEXT,
    vuln_type         TEXT,
    severity          TEXT,
    affected_versions TEXT,
    fixed_versions    TEXT,
    remediation       TEXT,
    references_json   TEXT,
    published         INTEGER,
    fetched           INTEGER,
    url               TEXT
);

CREATE VIRTUAL TABLE IF NOT EXISTS advisories_fts USING fts5(
    external_id,
    title,
    summary,
    component,
    vuln_type,
    content='advisories',
    content_rowid='rowid'
);

CREATE TRIGGER IF NOT EXISTS advisories_ai AFTER INSERT ON advisories BEGIN
    INSERT INTO advisories_fts(rowid, external_id, title, summary, component, vuln_type)
    VALUES (new.rowid, new.external_id, new.title, new.summary, new.component, new.vuln_type);
END;
CREATE TRIGGER IF NOT EXISTS advisories_ad AFTER DELETE ON advisories BEGIN
    INSERT INTO advisories_fts(advisories_fts, rowid, external_id, title, summary, component, vuln_type)
    VALUES ('delete', old.rowid, old.external_id, old.title, old.summary, old.component, old.vuln_type);
END;
CREATE TRIGGER IF NOT EXISTS advisories_au AFTER UPDATE ON advisories BEGIN
    INSERT INTO advisories_fts(advisories_fts, rowid, external_id, title, summary, component, vuln_type)
    VALUES ('delete', old.rowid, old.external_id, old.title, old.summary, old.component, old.vuln_type);
    INSERT INTO advisories_fts(rowid, external_id, title, summary, component, vuln_type)
    VALUES (new.rowid, new.external_id, new.title, new.summary, new.component, new.vuln_type);
END;
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("migration: %w", err)
	}
	return s.addColumnIfMissing("advisories", "remediation", "TEXT")
}

// addColumnIfMissing fait évoluer les bases créées avant l'ajout d'une colonne.
func (s *Store) addColumnIfMissing(table, column, typ string) error {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, table, column,
	).Scan(&n)
	if err != nil {
		return fmt.Errorf("migration %s.%s: %w", table, column, err)
	}
	if n > 0 {
		return nil
	}
	if _, err := s.db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, column, typ)); err != nil {
		return fmt.Errorf("migration %s.%s: %w", table, column, err)
	}
	return nil
}

// Upsert insère ou remplace une liste d'advisories dans une transaction.
// Renvoie le nombre d'entrées écrites.
func (s *Store) Upsert(advs []model.Advisory) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
INSERT INTO advisories
  (id, source, external_id, title, summary, component, vuln_type, severity,
   affected_versions, fixed_versions, remediation, references_json, published, fetched, url)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
   source=excluded.source, external_id=excluded.external_id, title=excluded.title,
   summary=excluded.summary, component=excluded.component, vuln_type=excluded.vuln_type,
   severity=excluded.severity, affected_versions=excluded.affected_versions,
   fixed_versions=excluded.fixed_versions, remediation=excluded.remediation,
   references_json=excluded.references_json,
   published=excluded.published, fetched=excluded.fetched, url=excluded.url`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	n := 0
	for _, a := range advs {
		if a.Fetched.IsZero() {
			a.Fetched = time.Now()
		}
		_, err := stmt.Exec(
			a.ID, a.Source, a.ExternalID, a.Title, a.Summary, a.Component,
			a.VulnType, a.Severity, a.AffectedVersions, a.FixedVersions, a.Remediation,
			strings.Join(a.References, "\n"), unix(a.Published), unix(a.Fetched), a.URL,
		)
		if err != nil {
			return n, fmt.Errorf("upsert %s: %w", a.ID, err)
		}
		n++
	}
	return n, tx.Commit()
}

// Search interroge l'index plein-texte. Une requête vide renvoie les
// entrées les plus récentes.
func (s *Store) Search(query string, limit int) ([]model.Advisory, error) {
	if limit <= 0 {
		limit = 50
	}
	var (
		rows *sql.Rows
		err  error
	)
	if strings.TrimSpace(query) == "" {
		rows, err = s.db.Query(`
SELECT id, source, external_id, title, summary, component, vuln_type, severity,
       affected_versions, fixed_versions, remediation, references_json, published, fetched, url
FROM advisories ORDER BY published DESC LIMIT ?`, limit)
	} else {
		rows, err = s.db.Query(`
SELECT a.id, a.source, a.external_id, a.title, a.summary, a.component, a.vuln_type,
       a.severity, a.affected_versions, a.fixed_versions, a.remediation, a.references_json,
       a.published, a.fetched, a.url
FROM advisories_fts f
JOIN advisories a ON a.rowid = f.rowid
WHERE advisories_fts MATCH ?
ORDER BY rank LIMIT ?`, ftsQuery(query), limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scan(rows)
}

// Ref désigne brièvement une entrée, pour les renvois entre sources.
type Ref struct {
	ID    string // identifiant principal, sans les alias
	Title string
	URL   string
}

var cveRe = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// CVEIndex associe chaque CVE cité dans les identifiants d'une source aux
// entrées de cette source qui le mentionnent.
func (s *Store) CVEIndex(source string) (map[string][]Ref, error) {
	rows, err := s.db.Query(`SELECT external_id, title, url FROM advisories WHERE source = ?`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	idx := map[string][]Ref{}
	for rows.Next() {
		var ext, title, u string
		if err := rows.Scan(&ext, &title, &u); err != nil {
			return nil, err
		}
		ref := Ref{ID: strings.Fields(ext + " ")[0], Title: title, URL: u}
		for _, c := range cveRe.FindAllString(ext, -1) {
			idx[c] = append(idx[c], ref)
		}
	}
	return idx, rows.Err()
}

// CVEs renvoie les identifiants CVE présents dans une chaîne.
func CVEs(s string) []string { return cveRe.FindAllString(s, -1) }

// LastFetched renvoie la date de la collecte la plus récente d'une source
// (zéro si elle n'a jamais été collectée).
func (s *Store) LastFetched(source string) (time.Time, error) {
	var n sql.NullInt64
	err := s.db.QueryRow(`SELECT MAX(fetched) FROM advisories WHERE source = ?`, source).Scan(&n)
	if err != nil || !n.Valid {
		return time.Time{}, err
	}
	return fromUnix(n.Int64), nil
}

// Count renvoie le nombre total d'entrées stockées.
func (s *Store) Count() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM advisories`).Scan(&n)
	return n, err
}

func scan(rows *sql.Rows) ([]model.Advisory, error) {
	var out []model.Advisory
	for rows.Next() {
		var a model.Advisory
		var refs string
		var remediation sql.NullString
		var pub, fetched int64
		if err := rows.Scan(
			&a.ID, &a.Source, &a.ExternalID, &a.Title, &a.Summary, &a.Component,
			&a.VulnType, &a.Severity, &a.AffectedVersions, &a.FixedVersions,
			&remediation, &refs, &pub, &fetched, &a.URL,
		); err != nil {
			return nil, err
		}
		a.Remediation = remediation.String
		if refs != "" {
			a.References = strings.Split(refs, "\n")
		}
		a.Published = fromUnix(pub)
		a.Fetched = fromUnix(fetched)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ftsQuery transforme une saisie utilisateur libre en requête FTS5 sûre :
// chaque terme devient un préfixe entre guillemets, ce qui évite les erreurs
// de syntaxe sur des caractères comme '-' ou ':' (présents dans les CVE).
func ftsQuery(q string) string {
	fields := strings.Fields(q)
	for i, f := range fields {
		f = strings.ReplaceAll(f, `"`, "")
		fields[i] = `"` + f + `"*`
	}
	return strings.Join(fields, " ")
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func fromUnix(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0)
}
