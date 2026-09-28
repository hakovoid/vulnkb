package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// withVersion ajoute la version au terme quand elle est connue :
// « npm:axios » + « 1.6.0 » → « npm:axios@1.6.0 ».
func withVersion(term, version string) string {
	if version == "" {
		return term
	}
	return term + "@" + version
}

var exactRe = regexp.MustCompile(`^\d+(\.\d+)+([-+][0-9A-Za-z.+-]+)?$`)

// exactVersion renvoie la version d'une contrainte figée (« 1.2.3 »,
// « =1.2.3 », « v1.2.3 »), "" pour une plage (« ^1.2 », « >=1.0 », « * »).
func exactVersion(spec string) string {
	v := strings.TrimPrefix(strings.TrimSpace(spec), "=")
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if exactRe.MatchString(v) {
		return v
	}
	return ""
}

// npmLocks garde les fichiers package-lock.json déjà lus : un monorepo en a
// un seul pour tous ses paquets.
var npmLocks = map[string]*npmLockFile{}

type npmLockFile struct {
	dir      string
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
	Dependencies map[string]struct { // format v1
		Version string `json:"version"`
	} `json:"dependencies"`
}

// npmLock cherche le package-lock.json du projet (dans le dossier ou ses
// parents, pour les espaces de travail) et renvoie une fonction qui donne la
// version installée d'une dépendance, "" si inconnue.
func npmLock(dir string) func(name string) string {
	var lf *npmLockFile
	for d, i := dir, 0; i < 4; d, i = filepath.Dir(d), i+1 {
		path := filepath.Join(d, "package-lock.json")
		if l, ok := npmLocks[path]; ok {
			lf = l
			break
		}
		b, err := os.ReadFile(path)
		if err != nil {
			if filepath.Dir(d) == d {
				break
			}
			continue
		}
		l := &npmLockFile{dir: d}
		if json.Unmarshal(b, l) != nil {
			l = nil
		}
		npmLocks[path] = l
		lf = l
		break
	}
	if lf == nil {
		return func(string) string { return "" }
	}
	rel, _ := filepath.Rel(lf.dir, dir)
	rel = filepath.ToSlash(rel)
	return func(name string) string {
		if rel != "." && rel != "" {
			if p, ok := lf.Packages[rel+"/node_modules/"+name]; ok && p.Version != "" {
				return p.Version
			}
		}
		if p, ok := lf.Packages["node_modules/"+name]; ok && p.Version != "" {
			return p.Version
		}
		return lf.Dependencies[name].Version
	}
}

// pyKey normalise un nom de paquet Python (PEP 503).
func pyKey(name string) string {
	return strings.NewReplacer("_", "-", ".", "-").Replace(strings.ToLower(name))
}

var pyPinRe = regexp.MustCompile(`===?\s*([0-9][^\s,;*]*)\s*(?:$|[,;#\s])`)

// pyVersion renvoie la version figée d'une ligne de dépendance Python
// (« fastapi==0.109.2 »), sinon celle du fichier de verrouillage.
func pyVersion(spec, locked string) string {
	if m := pyPinRe.FindStringSubmatch(spec + " "); m != nil {
		return m[1]
	}
	return locked
}

// pyLock lit poetry.lock ou uv.lock à côté du fichier de dépendances.
func pyLock(dir string) map[string]string {
	for _, name := range []string{"poetry.lock", "uv.lock"} {
		if m := lockVersions(filepath.Join(dir, name), parseTOMLPackages); len(m) > 0 {
			out := map[string]string{}
			for k, v := range m {
				out[pyKey(k)] = v
			}
			return out
		}
	}
	return nil
}

// lockVersions lit un fichier de verrouillage s'il existe : nom du paquet
// (en minuscules) → versions séparées par des virgules.
func lockVersions(path string, parse func([]byte) map[string]string) map[string]string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parse(b)
}

// parseTOMLPackages lit les blocs [[package]] (name, version) de Cargo.lock,
// poetry.lock et uv.lock. Un paquet présent en plusieurs versions les garde
// toutes.
func parseTOMLPackages(b []byte) map[string]string {
	out := map[string]string{}
	add := func(name, ver string) {
		if name == "" || ver == "" {
			return
		}
		name = strings.ToLower(name)
		for _, v := range strings.Split(out[name], ",") {
			if v == ver {
				return
			}
		}
		if out[name] != "" {
			ver = out[name] + "," + ver
		}
		out[name] = ver
	}
	var name, ver string
	in := false
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == "[[package]]":
			add(name, ver)
			name, ver, in = "", "", true
		case strings.HasPrefix(t, "["):
			add(name, ver)
			name, ver, in = "", "", false
		case in && strings.HasPrefix(t, "name"):
			if k, v, ok := strings.Cut(t, "="); ok && strings.TrimSpace(k) == "name" {
				name = strings.Trim(strings.TrimSpace(v), `"'`)
			}
		case in && strings.HasPrefix(t, "version"):
			if k, v, ok := strings.Cut(t, "="); ok && strings.TrimSpace(k) == "version" {
				ver = strings.Trim(strings.TrimSpace(v), `"'`)
			}
		}
	}
	add(name, ver)
	return out
}

// parseComposerLock lit les paquets de composer.lock (dépendances et
// dépendances de développement).
func parseComposerLock(b []byte) map[string]string {
	var l struct {
		Packages    []struct{ Name, Version string } `json:"packages"`
		PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
	}
	if json.Unmarshal(b, &l) != nil {
		return nil
	}
	out := map[string]string{}
	for _, p := range append(l.Packages, l.PackagesDev...) {
		out[strings.ToLower(p.Name)] = strings.TrimPrefix(p.Version, "v")
	}
	return out
}
