package store

import (
	"database/sql"
	"strings"

	sqlite3 "github.com/mattn/go-sqlite3"

	"vulnkb/internal/model"
	"vulnkb/internal/versions"
)

// driverName est le pilote SQLite de vulnkb : go-sqlite3 augmenté de la
// fonction vk_affected(versions, introduced, fixed, last_affected), qui dit
// si l'une des versions (séparées par des virgules) tombe dans la plage. Elle
// permet de filtrer par version dans la requête elle-même, pagination et
// comptage compris.
const driverName = "sqlite3_vulnkb"

func init() {
	sql.Register(driverName, &sqlite3.SQLiteDriver{
		ConnectHook: func(c *sqlite3.SQLiteConn) error {
			return c.RegisterFunc("vk_affected", versions.AnyInRange, true)
		},
	})
}

// rangesSchema : plages de versions vulnérables, par entrée et par paquet.
const rangesSchema = `
CREATE TABLE IF NOT EXISTS advisory_ranges (
    id            TEXT NOT NULL,
    eco           TEXT NOT NULL,
    pkg           TEXT NOT NULL,
    introduced    TEXT,
    fixed         TEXT,
    last_affected TEXT
);
CREATE INDEX IF NOT EXISTS advisory_ranges_id ON advisory_ranges(id, eco, pkg);
`

func writeRanges(tx *sql.Tx, id string, ranges []model.Range) error {
	if _, err := tx.Exec(`DELETE FROM advisory_ranges WHERE id = ?`, id); err != nil {
		return err
	}
	for _, r := range ranges {
		if _, err := tx.Exec(`INSERT INTO advisory_ranges (id, eco, pkg, introduced, fixed, last_affected) VALUES (?,?,?,?,?,?)`,
			id, r.Ecosystem, r.Package, r.Introduced, r.Fixed, r.LastAffected); err != nil {
			return err
		}
	}
	return nil
}

// WatchTerm est un terme de la liste de surveillance décomposé :
// « npm:axios@1.6.0,1.7.2 » → écosystème npm, paquet axios, deux versions.
type WatchTerm struct {
	Raw       string
	Ecosystem string // préfixe connu (npm, pypi…), "" pour un terme simple
	Label     string // nom de l'écosystème dans les fiches (« crates.io »)
	Package   string // nom normalisé
	Name      string // nom tel qu'écrit (terme simple : le mot cherché)
	Versions  string // versions utilisées, séparées par des virgules ; "" = toutes
}

// ParseWatchTerm décompose un terme de la liste de surveillance.
func ParseWatchTerm(raw string) WatchTerm {
	t := WatchTerm{Raw: raw, Name: strings.TrimSpace(strings.ReplaceAll(raw, `"`, ""))}
	eco, rest, ok := strings.Cut(t.Name, ":")
	e, known := watchEcosystems[strings.ToLower(eco)]
	if !ok || !known || rest == "" {
		return t
	}
	// « @ » sépare la version ; un paquet npm à portée (« @scope/pkg ») en
	// commence par un
	name, ver := rest, ""
	if i := strings.LastIndexByte(rest, '@'); i > 0 {
		name, ver = rest[:i], rest[i+1:]
	}
	t.Ecosystem, t.Label, t.Name = strings.ToLower(eco), e.label, name
	t.Package = model.NormalizePackage(e.label, name)
	t.Versions = strings.Join(strings.Fields(strings.ReplaceAll(ver, ",", " ")), ",")
	return t
}

// versionCond restreint le filtre d'un paquet aux entrées qui touchent l'une
// des versions utilisées. Une entrée sans plage exploitable pour ce paquet
// est gardée : mieux vaut un faux positif qu'une faille manquée.
func versionCond(t WatchTerm) (string, []any) {
	return `(NOT EXISTS (SELECT 1 FROM advisory_ranges r WHERE r.id = a.id AND r.eco = ? AND r.pkg = ?)
     OR EXISTS (SELECT 1 FROM advisory_ranges r WHERE r.id = a.id AND r.eco = ? AND r.pkg = ?
                AND vk_affected(?, r.introduced, r.fixed, r.last_affected)))`,
		[]any{t.Label, t.Package, t.Label, t.Package, t.Versions}
}

// VersionHit est une version surveillée touchée par une entrée.
type VersionHit struct {
	Ecosystem, Package, Version string
	Fixed                       string // version corrective de la plage, "" si inconnue
}

// WatchedVersionsHit renvoie, pour une entrée, les versions de la liste de
// surveillance qu'elle touche (termes qualifiés avec version seulement).
func (s *Store) WatchedVersionsHit(id string) ([]VersionHit, error) {
	// les plages de l'entrée d'abord (quelques lignes), comparées ensuite à
	// la liste en mémoire
	rows, err := s.db.Query(`SELECT eco, pkg, IFNULL(introduced, ''), IFNULL(fixed, ''), IFNULL(last_affected, '')
FROM advisory_ranges WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	var ranges []model.Range
	for rows.Next() {
		var r model.Range
		if err := rows.Scan(&r.Ecosystem, &r.Package, &r.Introduced, &r.Fixed, &r.LastAffected); err != nil {
			rows.Close()
			return nil, err
		}
		ranges = append(ranges, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(ranges) == 0 {
		return nil, err
	}
	var out []VersionHit
	for _, raw := range Watchlist() {
		t := ParseWatchTerm(raw)
		if t.Versions == "" {
			continue
		}
		for _, v := range strings.Split(t.Versions, ",") {
			for _, r := range ranges {
				if r.Ecosystem == t.Label && r.Package == t.Package && versions.InRange(v, r.Introduced, r.Fixed, r.LastAffected) {
					out = append(out, VersionHit{Ecosystem: t.Label, Package: t.Name, Version: v, Fixed: r.Fixed})
					break
				}
			}
		}
	}
	return out, nil
}
