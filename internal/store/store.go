// Package store gère la persistance des advisories dans SQLite, avec un
// index de recherche plein-texte (FTS5) pour interroger rapidement.
package store

import (
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
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

-- Scores CVSS de la base NVD, par CVE.
CREATE TABLE IF NOT EXISTS nvd_scores (
    cve     TEXT PRIMARY KEY,
    score   REAL NOT NULL,
    level   INTEGER NOT NULL,
    version TEXT,
    vector  TEXT,
    source  TEXT,
    cwe     TEXT
);

CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT
);

-- Exploits et preuves de concept publics, par CVE.
CREATE TABLE IF NOT EXISTS exploit_refs (
    cve   TEXT NOT NULL,
    kind  TEXT NOT NULL,
    title TEXT,
    url   TEXT NOT NULL,
    stars INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cve, url)
);
CREATE INDEX IF NOT EXISTS exploit_refs_cve ON exploit_refs(cve);
`

// bestNVD sélectionne, pour l'entrée « a », le score NVD le plus élevé
// parmi ses CVE.
const bestNVD = `(SELECT n.cve || '|' || n.score || '|' || n.level || '|' || IFNULL(n.version, '') || '|' ||
       IFNULL(n.source, '') || '|' || IFNULL(n.cwe, '') || '|' || IFNULL(n.vector, '')
   FROM advisory_cves c JOIN nvd_scores n ON n.cve = c.cve
   WHERE c.id = a.id ORDER BY n.score DESC, n.cve LIMIT 1)`

// effectiveLevel calcule la sévérité de l'entrée, ou à défaut la plus haute
// sévérité NVD de ses CVE. Le résultat est stocké dans eff_level (voir
// RefreshLevels) pour que le filtre de sévérité reste instantané.
const effectiveLevel = `(CASE WHEN advisories.severity_level > 0 THEN advisories.severity_level ELSE COALESCE(
   (SELECT MAX(n.level) FROM advisory_cves c JOIN nvd_scores n ON n.cve = c.cve WHERE c.id = advisories.id), 0) END)`

// RefreshLevels recalcule la sévérité effective de toutes les entrées ; à
// appeler après une mise à jour des scores NVD.
func (s *Store) RefreshLevels() error {
	_, err := s.db.Exec(`UPDATE advisories SET eff_level = ` + effectiveLevel + ` WHERE eff_level <> ` + effectiveLevel)
	return err
}

// coveredElsewhere est vrai quand le CVE d'une entrée NVD a déjà une fiche
// propre dans une autre source (OSV, CISA KEV, article…). Les avis CERT-FR,
// qui regroupent souvent des dizaines de CVE, ne comptent pas.
const coveredElsewhere = `EXISTS (
    SELECT 1 FROM advisory_cves c JOIN advisory_cves o ON o.cve = c.cve
    WHERE c.id = advisories.id AND o.id <> c.id
      AND o.id NOT LIKE 'nvd:%' AND o.id NOT LIKE 'certfr:%')`

// RefreshShadowed masque les entrées NVD couvertes par une autre source, et
// démasque celles qui ne le sont plus.
func (s *Store) RefreshShadowed() error {
	_, err := s.db.Exec(`
UPDATE advisories SET shadowed = 1 WHERE source = 'nvd' AND shadowed = 0 AND ` + coveredElsewhere + `;
UPDATE advisories SET shadowed = 0 WHERE source = 'nvd' AND shadowed = 1 AND NOT ` + coveredElsewhere + `;`)
	return err
}

// kevLinked liste les entrées qui partagent un CVE avec le catalogue CISA KEV
// (les entrées KEV elles-mêmes comprises).
const kevLinked = `SELECT c.id FROM advisory_cves c
    JOIN advisory_cves k ON k.cve = c.cve AND k.id >= 'cisa-kev:' AND k.id < 'cisa-kev;'`

// RefreshExploited met à jour le marqueur « exploitée activement ».
func (s *Store) RefreshExploited() error {
	_, err := s.db.Exec(`
UPDATE advisories SET exploited = 1 WHERE exploited = 0 AND id IN (` + kevLinked + `);
UPDATE advisories SET exploited = 0 WHERE exploited = 1 AND id NOT IN (` + kevLinked + `);`)
	return err
}

// hasExploitLinked liste les entrées dont un CVE dispose d'un exploit public.
const hasExploitLinked = `SELECT c.id FROM advisory_cves c
    JOIN exploit_refs e ON e.cve = c.cve`

// RefreshHasExploit met à jour le marqueur « exploit public disponible ».
func (s *Store) RefreshHasExploit() error {
	_, err := s.db.Exec(`
UPDATE advisories SET has_exploit = 1 WHERE has_exploit = 0 AND id IN (` + hasExploitLinked + `);
UPDATE advisories SET has_exploit = 0 WHERE has_exploit = 1 AND id NOT IN (` + hasExploitLinked + `);`)
	return err
}

// RefreshDerived recalcule tout ce qui dépend de plusieurs sources à la fois ;
// à appeler en fin de synchro.
func (s *Store) RefreshDerived() error {
	for _, f := range []func() error{s.RefreshLevels, s.RefreshShadowed, s.RefreshExploited, s.RefreshHasExploit} {
		if err := f(); err != nil {
			return err
		}
	}
	return nil
}

// DeleteAdvisories supprime des entrées (ex. CVE rejetés par NVD).
func (s *Store) DeleteAdvisories(ids []string) error {
	return s.inTx(func(tx *sql.Tx) error {
		for _, id := range ids {
			if _, err := tx.Exec(`DELETE FROM advisories WHERE id = ?`, id); err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM advisory_cves WHERE id = ?`, id); err != nil {
				return err
			}
		}
		return nil
	})
}

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
CREATE TRIGGER IF NOT EXISTS advisories_au AFTER UPDATE OF ` + cols + ` ON advisories BEGIN
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
	sevAdded, err := s.addColumnIfMissing("advisories", "severity_level", "INTEGER NOT NULL DEFAULT 0")
	if err != nil {
		return err
	}
	effAdded, err := s.addColumnIfMissing("advisories", "eff_level", "INTEGER NOT NULL DEFAULT 0")
	if err != nil {
		return err
	}
	if _, err := s.addColumnIfMissing("advisories", "shadowed", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	exploitedAdded, err := s.addColumnIfMissing("advisories", "exploited", "INTEGER NOT NULL DEFAULT 0")
	if err != nil {
		return err
	}
	exploitAdded, err := s.addColumnIfMissing("advisories", "has_exploit", "INTEGER NOT NULL DEFAULT 0")
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`
DROP INDEX IF EXISTS advisories_source;
CREATE INDEX IF NOT EXISTS advisories_source_pub ON advisories(source, published DESC, id);
CREATE INDEX IF NOT EXISTS advisories_exploited ON advisories(exploited);
CREATE INDEX IF NOT EXISTS advisories_has_exploit ON advisories(has_exploit);`); err != nil {
		return fmt.Errorf("migration index: %w", err)
	}
	if _, err := s.db.Exec(`
CREATE INDEX IF NOT EXISTS advisories_severity ON advisories(severity_level);
CREATE INDEX IF NOT EXISTS advisories_eff_level ON advisories(eff_level);
CREATE INDEX IF NOT EXISTS advisories_shadowed ON advisories(shadowed, published DESC, id);`); err != nil {
		return fmt.Errorf("migration index: %w", err)
	}
	// l'index plein-texte d'abord : ses triggers ne doivent pas réagir aux
	// mises à jour de masse qui suivent
	if err := s.migrateFTS(); err != nil {
		return err
	}
	if sevAdded {
		if err := s.backfillSeverity(); err != nil {
			return err
		}
	}
	if err := s.backfillCVEs(); err != nil {
		return err
	}
	if exploitedAdded {
		if err := s.RefreshExploited(); err != nil {
			return err
		}
	}
	if exploitAdded {
		if err := s.RefreshHasExploit(); err != nil {
			return err
		}
	}
	if sevAdded || effAdded {
		return s.RefreshLevels()
	}
	return nil
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
	// ancien trigger de mise à jour, déclenché par n'importe quelle colonne
	var auSQL string
	s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'advisories_au'`).Scan(&auSQL)
	if auSQL != "" && !strings.Contains(auSQL, "UPDATE OF") {
		if _, err := s.db.Exec(`DROP TRIGGER advisories_au`); err != nil {
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
		if _, err := tx.Exec(`UPDATE advisories SET eff_level = `+effectiveLevel+`,
    exploited = (id IN (`+kevLinked+` WHERE c.id = ?)) WHERE id = ?`, a.ID, a.ID); err != nil {
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

// SearchPage renvoie limit résultats à partir du rang offset (0 = premier),
// dans l'ordre par défaut (pertinence/date).
func (s *Store) SearchPage(query string, offset, limit int) ([]model.Advisory, error) {
	return s.SearchPageSorted(query, SortAuto, offset, limit)
}

// SearchPageSorted est SearchPage avec un mode de tri explicite. La saisie
// peut mêler texte et filtres (voir Query). L'ordre est stable d'une page à
// l'autre.
func (s *Store) SearchPageSorted(query string, sort Sort, offset, limit int) ([]model.Advisory, error) {
	if limit <= 0 {
		limit = 50
	}
	q := ParseQuery(query)
	if q.Impossible() {
		return nil, nil
	}
	// Deux temps : les identifiants de la page d'abord, puis le détail de ces
	// seules entrées. En une requête, SQLite calculerait le score NVD de
	// toutes les entrées filtrées avant de trier.
	from, fts, args := searchFrom(q)
	order := orderBy(sort, fts)
	args = append(args, limit, max(0, offset))
	idRows, err := s.db.Query(`SELECT a.id `+from+` ORDER BY `+order+` LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, err
	}
	var ids []any
	for idRows.Next() {
		var id string
		if err := idRows.Scan(&id); err != nil {
			idRows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	idRows.Close()
	if err := idRows.Err(); err != nil || len(ids) == 0 {
		return nil, err
	}

	rows, err := s.db.Query(`
SELECT a.id, a.source, a.external_id, a.title, a.summary, a.component, a.vuln_type,
       a.severity, a.affected_versions, a.fixed_versions, a.remediation, a.references_json,
       a.published, a.fetched, a.url, `+bestNVD+`
FROM advisories a WHERE a.id IN (`+placeholders(len(ids))+`)`, ids...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found, err := scan(rows)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]model.Advisory, len(found))
	for _, a := range found {
		byID[a.ID] = a
	}
	out := make([]model.Advisory, 0, len(ids))
	for _, id := range ids {
		if a, ok := byID[id.(string)]; ok {
			out = append(out, a)
		}
	}
	return out, nil
}

// UpsertNVD enregistre des scores NVD dans une transaction. Appeler
// RefreshLevels ensuite pour qu'ils comptent dans le filtre de sévérité.
func (s *Store) UpsertNVD(scores []model.CVSS) error {
	return s.inTx(func(tx *sql.Tx) error {
		stmt, err := tx.Prepare(`INSERT OR REPLACE INTO nvd_scores (cve, score, level, version, vector, source, cwe)
VALUES (?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, c := range scores {
			if _, err := stmt.Exec(c.CVE, c.Score, c.Level, c.Version, c.Vector, c.Source, c.CWE); err != nil {
				return fmt.Errorf("score NVD %s: %w", c.CVE, err)
			}
		}
		return nil
	})
}

// CountNVD renvoie le nombre de CVE dotés d'un score NVD.
func (s *Store) CountNVD() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM nvd_scores`).Scan(&n)
	return n, err
}

// ReplaceExploits remplace toute la table des exploits par refs (les sources
// sont re-collectées en entier à chaque synchro, et les dépôts PoC vont et
// viennent). Appeler RefreshDerived ensuite pour le filtre « exploit ».
func (s *Store) ReplaceExploits(refs []model.ExploitRef) error {
	return s.inTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM exploit_refs`); err != nil {
			return err
		}
		stmt, err := tx.Prepare(`INSERT OR IGNORE INTO exploit_refs (cve, kind, title, url, stars) VALUES (?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, r := range refs {
			if _, err := stmt.Exec(r.CVE, r.Kind, r.Title, r.URL, r.Stars); err != nil {
				return fmt.Errorf("exploit %s: %w", r.CVE, err)
			}
		}
		return nil
	})
}

// CountExploits renvoie le nombre de références d'exploits stockées.
func (s *Store) CountExploits() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM exploit_refs`).Scan(&n)
	return n, err
}

// ExploitsFor renvoie les exploits publics liés à une liste de CVE, modules
// Metasploit et Exploit-DB d'abord, puis dépôts PoC les plus étoilés.
func (s *Store) ExploitsFor(cves []string) ([]model.ExploitRef, error) {
	if len(cves) == 0 {
		return nil, nil
	}
	args := make([]any, len(cves))
	for i, c := range cves {
		args[i] = c
	}
	rows, err := s.db.Query(`SELECT cve, kind, title, url, stars FROM exploit_refs
WHERE cve IN (`+placeholders(len(cves))+`)
ORDER BY CASE kind WHEN 'msf' THEN 0 WHEN 'edb' THEN 1 ELSE 2 END, stars DESC, url`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ExploitRef
	for rows.Next() {
		var e model.ExploitRef
		if err := rows.Scan(&e.CVE, &e.Kind, &e.Title, &e.URL, &e.Stars); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Meta lit une valeur de suivi (date de dernière synchro…) ; "" si absente.
func (s *Store) Meta(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT v FROM meta WHERE k = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// SetMeta enregistre une valeur de suivi.
func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)`, key, value)
	return err
}

// CountMatches renvoie le nombre total de résultats d'une recherche.
func (s *Store) CountMatches(query string) (int, error) {
	q := ParseQuery(query)
	if q.Impossible() {
		return 0, nil
	}
	from, _, args := searchFrom(q) // le tri ne change pas le total
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) `+from, args...).Scan(&n)
	return n, err
}

// Sort choisit l'ordre des résultats.
type Sort int

const (
	SortAuto     Sort = iota // pertinence si recherche texte, sinon date
	SortDate                 // date de publication décroissante
	SortSeverity             // criticité décroissante, puis date
)

// SortLabel nomme un mode de tri pour l'affichage.
func SortLabel(s Sort) string {
	switch s {
	case SortDate:
		return "date"
	case SortSeverity:
		return "criticité"
	default:
		return "pertinence"
	}
}

// searchFrom renvoie les clauses FROM/WHERE d'une recherche et si elle porte
// sur l'index plein-texte. La recherche plein-texte réunit le texte libre et,
// le cas échéant, le filtre « mes » (produits surveillés).
func searchFrom(q Query) (from string, fts bool, args []any) {
	filter, fargs := q.where()
	match := q.matchExpr()
	if match == "" {
		return `FROM advisories a WHERE 1=1` + filter, false, fargs
	}
	// CROSS JOIN impose de partir de l'index plein-texte : sinon SQLite peut
	// parcourir toutes les entrées visibles et interroger l'index pour chacune.
	return `FROM advisories_fts f CROSS JOIN advisories a ON a.rowid = f.rowid
WHERE advisories_fts MATCH ?` + filter, true, append([]any{match}, fargs...)
}

// orderBy renvoie la clause ORDER BY selon le mode de tri.
func orderBy(sort Sort, fts bool) string {
	switch sort {
	case SortDate:
		return `a.published DESC, a.id`
	case SortSeverity:
		return `a.eff_level DESC, a.published DESC, a.id`
	default:
		if fts {
			return `f.rank, a.id`
		}
		return `a.published DESC, a.id`
	}
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

// FetchedTimes renvoie, pour une source, la date de collecte de chaque
// entrée (clé = identifiant interne). Sert aux sources incrémentales à
// savoir ce qu'elles ont déjà, et si une révision est plus récente.
func (s *Store) FetchedTimes(source string) (map[string]time.Time, error) {
	rows, err := s.db.Query(`SELECT id, fetched FROM advisories WHERE source = ?`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var id string
		var f int64
		if err := rows.Scan(&id, &f); err != nil {
			return nil, err
		}
		out[id] = fromUnix(f)
	}
	return out, rows.Err()
}

// LastSync renvoie la date de la collecte la plus récente, toutes sources
// confondues (zéro si la base est vide).
func (s *Store) LastSync() (time.Time, error) {
	var n sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(fetched) FROM advisories`).Scan(&n); err != nil || !n.Valid {
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

// DBSize renvoie la taille de la base en octets (pages × taille de page).
func (s *Store) DBSize() (int64, error) {
	var pages, pageSize int64
	if err := s.db.QueryRow(`PRAGMA page_count`).Scan(&pages); err != nil {
		return 0, err
	}
	if err := s.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		return 0, err
	}
	return pages * pageSize, nil
}

// CountsBySource renvoie le nombre d'entrées par source.
func (s *Store) CountsBySource() (map[string]int, error) {
	rows, err := s.db.Query(`SELECT source, COUNT(*) FROM advisories GROUP BY source ORDER BY 2 DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var src string
		var n int
		if err := rows.Scan(&src, &n); err != nil {
			return nil, err
		}
		out[src] = n
	}
	return out, rows.Err()
}

func scan(rows *sql.Rows) ([]model.Advisory, error) {
	var out []model.Advisory
	for rows.Next() {
		var a model.Advisory
		var refs string
		var remediation, nvd sql.NullString
		var pub, fetched int64
		if err := rows.Scan(
			&a.ID, &a.Source, &a.ExternalID, &a.Title, &a.Summary, &a.Component,
			&a.VulnType, &a.Severity, &a.AffectedVersions, &a.FixedVersions,
			&remediation, &refs, &pub, &fetched, &a.URL, &nvd,
		); err != nil {
			return nil, err
		}
		a.Remediation = remediation.String
		a.NVD = parseNVD(nvd.String)
		if refs != "" {
			a.References = strings.Split(refs, "\n")
		}
		a.Published = fromUnix(pub)
		a.Fetched = fromUnix(fetched)
		out = append(out, a)
	}
	return out, rows.Err()
}

// parseNVD relit la ligne produite par bestNVD.
func parseNVD(s string) model.CVSS {
	p := strings.SplitN(s, "|", 7)
	if len(p) != 7 {
		return model.CVSS{}
	}
	score, _ := strconv.ParseFloat(p[1], 64)
	level, _ := strconv.Atoi(p[2])
	return model.CVSS{CVE: p[0], Score: score, Level: level, Version: p[3], Source: p[4], CWE: p[5], Vector: p[6]}
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
