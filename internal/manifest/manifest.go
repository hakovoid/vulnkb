// Package manifest lit les fichiers de dépendances des projets (package.json,
// go.mod, requirements.txt, pyproject.toml, composer.json, Cargo.toml,
// docker-compose) pour en tirer la liste de surveillance de vulnkb.
//
// Une dépendance devient un terme qualifié par son écosystème, par exemple
// « npm:express » : la recherche ne vise alors que ce paquet exact dans le
// composant des fiches, sans bruit sur les titres. Une image Docker devient
// un terme simple (« redis », « ollama ») : c'est un produit, cherché partout.
package manifest

import (
	"bufio"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Options règle ce qui est importé.
type Options struct {
	Dev      bool // dépendances de développement (devDependencies…)
	Indirect bool // dépendances indirectes de go.mod
}

// Found est le résultat de la lecture d'un fichier.
type Found struct {
	File  string   // chemin relatif à la racine explorée
	Terms []string // termes de surveillance, dédoublonnés et triés
}

// skipDir liste les dossiers jamais explorés : dépendances installées,
// sorties de compilation, environnements Python, dépôts git.
var skipDir = map[string]bool{
	"node_modules": true, "vendor": true, "dist": true, "build": true, "target": true,
	".venv": true, "venv": true, "__pycache__": true, ".next": true, ".nuxt": true,
	".output": true, ".svelte-kit": true, ".astro": true, "coverage": true,
}

// Scan explore root et lit chaque fichier de dépendances rencontré. Les
// dossiers cachés et les copies de sauvegarde (nom contenant « backup » ou
// finissant par « -bck ») sont ignorés.
func Scan(root string, opt Options) ([]Found, error) {
	var out []Found
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // dossier illisible : on continue
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && (strings.HasPrefix(name, ".") || skipDir[name] ||
				strings.Contains(strings.ToLower(name), "backup") || strings.HasSuffix(name, "-bck")) {
				return filepath.SkipDir
			}
			return nil
		}
		terms := parseFile(path, name, opt)
		if len(terms) == 0 {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		out = append(out, Found{File: rel, Terms: dedup(terms)})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out, err
}

func parseFile(path, name string, opt Options) []string {
	lower := strings.ToLower(name)
	switch {
	case lower == "package.json":
		return parsePackageJSON(path, opt)
	case lower == "go.mod":
		return parseGoMod(path, opt)
	case lower == "requirements.txt" || (strings.HasPrefix(lower, "requirements") && strings.HasSuffix(lower, ".txt")):
		return parseRequirements(path)
	case lower == "pyproject.toml":
		return parsePyproject(path)
	case lower == "composer.json":
		return parseComposer(path)
	case lower == "cargo.toml":
		return parseCargo(path)
	case strings.HasPrefix(lower, "docker-compose") && (strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")),
		lower == "compose.yml", lower == "compose.yaml":
		return parseCompose(path)
	}
	return nil
}

func parsePackageJSON(path string, opt Options) []string {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if b, err := os.ReadFile(path); err != nil || json.Unmarshal(b, &pkg) != nil {
		return nil
	}
	var out []string
	add := func(deps map[string]string) {
		for name, ver := range deps {
			if strings.HasPrefix(ver, "file:") || strings.HasPrefix(ver, "workspace:") || strings.HasPrefix(ver, "link:") {
				continue // paquet local, pas de faille publique
			}
			out = append(out, "npm:"+name)
		}
	}
	add(pkg.Dependencies)
	if opt.Dev {
		add(pkg.DevDependencies)
	}
	return out
}

var goRequireRe = regexp.MustCompile(`^\s*(?:require\s+)?([a-zA-Z0-9][\w.\-/~]*\.[\w.\-/~]+)\s+v\S+(.*)$`)

func parseGoMod(path string, opt Options) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	inBlock := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "require ("):
			inBlock = true
			continue
		case inBlock && t == ")":
			inBlock = false
			continue
		case !inBlock && !strings.HasPrefix(t, "require "):
			continue
		}
		m := goRequireRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if !opt.Indirect && strings.Contains(m[2], "// indirect") {
			continue
		}
		out = append(out, "go:"+m[1])
	}
	return out
}

// pyName extrait le nom d'un paquet d'une ligne de dépendance Python
// (« uvicorn[standard]>=0.29,<1.0 » → « uvicorn »).
var pyNameRe = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)`)

func pyName(spec string) string {
	if m := pyNameRe.FindStringSubmatch(spec); m != nil {
		return strings.ToLower(m[1])
	}
	return ""
}

func parseRequirements(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "-") || strings.Contains(t, "://") {
			continue // commentaire, option (-r, -e…), URL
		}
		if n := pyName(t); n != "" {
			out = append(out, "pypi:"+n)
		}
	}
	return out
}

var quotedRe = regexp.MustCompile(`"([^"]+)"|'([^']+)'`)

// parsePyproject lit [project] dependencies et [tool.poetry.dependencies].
func parsePyproject(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	section, inDeps := "", false
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") && !inDeps {
			section = t
			continue
		}
		switch {
		case section == "[project]" && strings.HasPrefix(t, "dependencies") && strings.Contains(t, "["):
			inDeps = !strings.Contains(t, "]")
			for _, m := range quotedRe.FindAllStringSubmatch(t, -1) {
				if n := pyName(m[1] + m[2]); n != "" {
					out = append(out, "pypi:"+n)
				}
			}
		case inDeps:
			if strings.HasPrefix(t, "]") {
				inDeps = false
				continue
			}
			for _, m := range quotedRe.FindAllStringSubmatch(t, -1) {
				if n := pyName(m[1] + m[2]); n != "" {
					out = append(out, "pypi:"+n)
				}
			}
		case section == "[tool.poetry.dependencies]" && strings.Contains(t, "="):
			if n := pyName(t); n != "" && n != "python" {
				out = append(out, "pypi:"+n)
			}
		}
	}
	return out
}

func parseComposer(path string) []string {
	var c struct {
		Require map[string]string `json:"require"`
	}
	if b, err := os.ReadFile(path); err != nil || json.Unmarshal(b, &c) != nil {
		return nil
	}
	var out []string
	for name := range c.Require {
		if name == "php" || strings.HasPrefix(name, "ext-") || !strings.Contains(name, "/") {
			continue
		}
		out = append(out, "packagist:"+name)
	}
	return out
}

var tomlKeyRe = regexp.MustCompile(`^\s*([A-Za-z0-9_-]+)\s*=`)

func parseCargo(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	section := ""
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			section = t
			continue
		}
		if section == "[dependencies]" {
			if m := tomlKeyRe.FindStringSubmatch(t); m != nil {
				out = append(out, "crates:"+m[1])
			}
		}
	}
	return out
}

var imageRe = regexp.MustCompile(`(?m)^\s*image:\s*['"]?([^\s'"#]+)`)

// parseCompose tire des images Docker le nom du produit : « redis:7-alpine »
// → « redis », « ghcr.io/open-webui/open-webui:main » → « open-webui ».
func parseCompose(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range imageRe.FindAllStringSubmatch(string(b), -1) {
		img := m[1]
		if strings.Contains(img, "${") {
			continue // image paramétrée par une variable
		}
		if i := strings.LastIndex(img, "/"); i >= 0 {
			img = img[i+1:]
		}
		img, _, _ = strings.Cut(img, "@")
		img, _, _ = strings.Cut(img, ":")
		if img != "" {
			out = append(out, strings.ToLower(img))
		}
	}
	return out
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
