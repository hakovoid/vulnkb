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

const tableSchema = `
CREATE TABLE IF NOT EXISTS advisories (
    id                TEXT PRIMARY KEY,
    source            TEXT NOT NULL,
    external_id       TEXT,
    title             TEXT,
    summary           TEXT,
    component         TEXT,
    vuln_type         TEXT,
    severity          TEXT,
    severity_level    INTEGER NOT NULL DEFAULT 0,
    affected_versions TEXT,
    fixed_versions    TEXT,
    remediation       TEXT,
    references_json   TEXT,
    published         INTEGER,
    fetched           INTEGER,
    url               TEXT
);

CREATE INDEX IF NOT EXISTS advisories_published ON advisories(published DESC, id);

-- CVE cités par chaque entrée (identifiant et alias), pour les recoupements
-- entre sources, dont le filtre « exploitée ».
CREATE TABLE IF NOT EXISTS advisory_cves (
    id  TEXT NOT NULL,
    cve TEXT NOT NULL,
    PRIMARY KEY (id, cve)
);
CREATE INDEX IF NOT EXISTS advisory_cves_cve ON advisory_cves(cve, id);
`

// ftsColumns sont les champs cherchés par la recherche plein-texte.
var ftsColumns = []string{"external_id", "title", "summary", "component", "vuln_type",
	"affected_versions", "fixed_versions", "remediation"}

func ftsSchema() string {
	cols := strings.Join(ftsColumns, ", ")
	newCols := "new." + strings.Join(ftsColumns, ", new.")
	oldCols := "old." + strings.Join(ftsColumns, ", old.")
	return `
CREATE VIRTUAL TABLE IF NOT EXISTS advisories_fts USING fts5(
    ` + cols + `,
    content='advisories',
    content_rowid='rowid'
);
CREATE TRIGGER IF NOT EXISTS advisories_ai AFTER INSERT ON advisories BEGIN
    INSERT INTO advisories_fts(rowid, ` + cols + `) VALUES (new.rowid, ` + newCols + `);
END;
CREATE TRIGGER IF NOT EXISTS advisories_ad AFTER DELETE ON advisories BEGIN
    INSERT INTO advisories_fts(advisories_fts, rowid, ` + cols + `) VALUES ('delete', old.rowid, ` + oldCols + `);
END;
CREATE TRIGGER IF NOT EXISTS advisories_au AFTER UPDATE ON advisories BEGIN
    INSERT INTO advisories_fts(advisories_fts, rowid, ` + cols + `) VALUES ('delete', old.rowid, ` + oldCols + `);
    INSERT INTO advisories_fts(rowid, ` + cols + `) VALUES (new.rowid, ` + newCols + `);
END;
`
}

// migrate crée le schéma, ou fait évoluer une base créée par une version
// antérieure. La table FTS5 est tenue à jour par des triggers.
func (s *Store) migrate() error {
	if _, err := s.db.Exec(tableSchema); err != nil {
		return fmt.Errorf("migration: %w", err)
	}
	if _, err := s.addColumnIfMissing("advisories", "remediation", "TEXT"); err != nil {
		return err
	}
	added, err := s.addColumnIfMissing("advisories", "severity_level", "INTEGER NOT NULL DEFAULT 0")
	if err != nil {
		return err
	}
	if added {
		if err := s.backfillSeverity(); err != nil {
			return err
		}
	}
	if _, err := s.db.Exec(`
CREATE INDEX IF NOT EXISTS advisories_source ON advisories(source);
CREATE INDEX IF NOT EXISTS advisories_severity ON advisories(severity_level);`); err != nil {
		return fmt.Errorf("migration index: %w", err)
	}
	if err := s.migrateFTS(); err != nil {
		return err
	}
	return s.backfillCVEs()
}

// migrateFTS crée l'index plein-texte, ou le reconstruit si ses colonnes ont
// changé depuis la création de la base.
func (s *Store) migrateFTS() error {
	var existing []string
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info('advisories_fts')`)
	if err != nil {
		return fmt.Errorf("migration fts: %w", err)
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		existing = append(existing, n)
	}
	rows.Close()

	rebuild := len(existing) > 0 && strings.Join(existing, ",") != strings.Join(ftsColumns, ",")
	if rebuild {
		if _, err := s.db.Exec(`
DROP TRIGGER IF EXISTS advisories_ai;
DROP TRIGGER IF EXISTS advisories_ad;
DROP TRIGGER IF EXISTS advisories_au;
DROP TABLE IF EXISTS advisories_fts;`); err != nil {
			return fmt.Errorf("migration fts: %w", err)
		}
	}
	if _, err := s.db.Exec(ftsSchema()); err != nil {
		return fmt.Errorf("migration fts: %w", err)
	}
	if rebuild || len(existing) == 0 {
		if _, err := s.db.Exec(`INSERT INTO advisories_fts(advisories_fts) VALUES ('rebuild')`); err != nil {
			return fmt.Errorf("reconstruction fts: %w", err)
		}
	}
	return nil
}

// backfillSeverity calcule le niveau de sévérité des entrées existantes.
func (s *Store) backfillSeverity() error {
	rows, err := s.db.Query(`SELECT id, severity FROM advisories`)
	if err != nil {
		return err
	}
	levels := map[string]int{}
	for rows.Next() {
		var id string
		var raw sql.NullString
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return err
		}
		if l := model.ParseSeverity(raw.String).Level; l != model.SevUnknown {
			levels[id] = l
		}
	}
	rows.Close()
	return s.inTx(func(tx *sql.Tx) error {
		for id, l := range levels {
			if _, err := tx.Exec(`UPDATE advisories SET severity_level = ? WHERE id = ?`, l, id); err != nil {
				return err
			}
		}
		return nil
	})
}

// backfillCVEs remplit la table des CVE si elle est vide alors que la base
// contient des entrées (base créée avant son introduction).
func (s *Store) backfillCVEs() error {
	var empty bool
	if err := s.db.QueryRow(`SELECT NOT EXISTS (SELECT 1 FROM advisory_cves) AND EXISTS (SELECT 1 FROM advisories)`).Scan(&empty); err != nil || !empty {
		return err
	}
	rows, err := s.db.Query(`SELECT id, external_id FROM advisories`)
	if err != nil {
		return err
	}
	ids := map[string]string{}
	for rows.Next() {
		var id string
		var ext sql.NullString
		if err := rows.Scan(&id, &ext); err != nil {
			rows.Close()
			return err
		}
		ids[id] = ext.String
	}
	rows.Close()
	return s.inTx(func(tx *sql.Tx) error {
		for id, ext := range ids {
			if err := writeCVEs(tx, id, ext); err != nil {
				return err
			}
		}
		return nil
	})
}

func writeCVEs(tx *sql.Tx, id, externalID string) error {
	if _, err := tx.Exec(`DELETE FROM advisory_cves WHERE id = ?`, id); err != nil {
		return err
	}
	for _, c := range CVEs(externalID) {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO advisory_cves(id, cve) VALUES (?, ?)`, id, c); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) inTx(fn func(*sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// addColumnIfMissing fait évoluer les bases créées avant l'ajout d'une
// colonne ; renvoie true si la colonne vient d'être ajoutée.
func (s *Store) addColumnIfMissing(table, column, typ string) (bool, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, table, column,
	).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("migration %s.%s: %w", table, column, err)
	}
	if n > 0 {
		return false, nil
	}
	if _, err := s.db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, column, typ)); err != nil {
		return false, fmt.Errorf("migration %s.%s: %w", table, column, err)
	}
	return true, nil
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
  (id, source, external_id, title, summary, component, vuln_type, severity, severity_level,
   affected_versions, fixed_versions, remediation, references_json, published, fetched, url)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
   source=excluded.source, external_id=excluded.external_id, title=excluded.title,
   summary=excluded.summary, component=excluded.component, vuln_type=excluded.vuln_type,
   severity=excluded.severity, severity_level=excluded.severity_level,
   affected_versions=excluded.affected_versions,
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
			a.VulnType, a.Severity, model.ParseSeverity(a.Severity).Level,
			a.AffectedVersions, a.FixedVersions, a.Remediation,
			strings.Join(a.References, "\n"), unix(a.Published), unix(a.Fetched), a.URL,
		)
		if err != nil {
			return n, fmt.Errorf("upsert %s: %w", a.ID, err)
		}
		if err := writeCVEs(tx, a.ID, a.ExternalID); err != nil {
			return n, fmt.Errorf("upsert %s: %w", a.ID, err)
		}
		n++
	}
	return n, tx.Commit()
}

// Search interroge l'index plein-texte. Une requête vide renvoie les
// entrées les plus récentes.
func (s *Store) Search(query string, limit int) ([]model.Advisory, error) {
	return s.SearchPage(query, 0, limit)
}

// SearchPage renvoie limit résultats à partir du rang offset (0 = premier).
// La saisie peut mêler texte et filtres (voir Query). L'ordre est stable
// d'une page à l'autre.
func (s *Store) SearchPage(query string, offset, limit int) ([]model.Advisory, error) {
	if limit <= 0 {
		limit = 50
	}
	from, order, args := searchFrom(ParseQuery(query))
	args = append(args, limit, max(0, offset))
	rows, err := s.db.Query(`
SELECT a.id, a.source, a.external_id, a.title, a.summary, a.component, a.vuln_type,
       a.severity, a.affected_versions, a.fixed_versions, a.remediation, a.references_json,
       a.published, a.fetched, a.url
`+from+` ORDER BY `+order+` LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scan(rows)
}

// CountMatches renvoie le nombre total de résultats d'une recherche.
func (s *Store) CountMatches(query string) (int, error) {
	from, _, args := searchFrom(ParseQuery(query))
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) `+from, args...).Scan(&n)
	return n, err
}

// searchFrom renvoie les clauses FROM/WHERE et ORDER BY d'une recherche.
func searchFrom(q Query) (from, order string, args []any) {
	filter, fargs := q.where()
	if strings.TrimSpace(q.Text) == "" {
		return `FROM advisories a WHERE 1=1` + filter, `a.published DESC, a.id`, fargs
	}
	return `FROM advisories_fts f JOIN advisories a ON a.rowid = f.rowid
WHERE advisories_fts MATCH ?` + filter, `f.rank, a.id`, append([]any{ftsQuery(q.Text)}, fargs...)
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
