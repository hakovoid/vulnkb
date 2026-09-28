package manifest

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScan(t *testing.T) {
	root := t.TempDir()
	write(t, root, "app/package.json", `{"dependencies":{"express":"^4","@astrojs/rss":"^4","local":"file:../lib"},
		"devDependencies":{"vite":"^6"}}`)
	write(t, root, "app/node_modules/x/package.json", `{"dependencies":{"ignored":"1"}}`)
	write(t, root, "svc/go.mod", "module x\n\ngo 1.25\n\nrequire (\n\tgithub.com/spf13/cobra v1.10.2\n\tcloud.google.com/go v0.116.0 // indirect\n)\n\nrequire gopkg.in/yaml.v3 v3.0.1\n")
	write(t, root, "py/requirements.txt", "# commentaire\nfastapi>=0.110,<1.0\nuvicorn[standard]>=0.29\n-r autres.txt\ngit+https://x/y.git\nPillow==10.4\n")
	write(t, root, "py/pyproject.toml", "[project]\nname = \"x\"\ndependencies = [\n  \"httpx>=0.27\",\n  'pydantic-settings>=2.0',\n]\n\n[tool.poetry.dependencies]\npython = \"^3.12\"\nrequests = \"^2\"\n")
	write(t, root, "php/composer.json", `{"require":{"php":">=8.2","ext-json":"*","monolog/monolog":"^3"}}`)
	write(t, root, "rs/Cargo.toml", "[package]\nname = \"x\"\n\n[dependencies]\nserde = \"1\"\ntokio = { version = \"1\" }\n\n[dev-dependencies]\ncriterion = \"0.5\"\n")
	write(t, root, "docker-compose.yml", "services:\n  a:\n    image: redis:7-alpine\n  b:\n    image: ghcr.io/open-webui/open-webui:main\n  c:\n    image: \"${IMAGE}\"\n  d:\n    build: .\n")
	write(t, root, "old-backup/package.json", `{"dependencies":{"vieux":"1"}}`)
	write(t, root, ".cache/package.json", `{"dependencies":{"cache":"1"}}`)

	found, err := Scan(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, f := range found {
		got[f.File] = f.Terms
	}
	want := map[string][]string{
		"app/package.json":    {"npm:@astrojs/rss", "npm:express"},
		"svc/go.mod":          {"go:github.com/spf13/cobra@1.10.2", "go:gopkg.in/yaml.v3@3.0.1"},
		"py/requirements.txt": {"pypi:fastapi", "pypi:pillow@10.4", "pypi:uvicorn"},
		"py/pyproject.toml":   {"pypi:httpx", "pypi:pydantic-settings", "pypi:requests"},
		"php/composer.json":   {"packagist:monolog/monolog"},
		"rs/Cargo.toml":       {"crates:serde", "crates:tokio"},
		"docker-compose.yml":  {"open-webui", "redis"},
	}
	if !reflect.DeepEqual(got, want) {
		for k, v := range got {
			if !reflect.DeepEqual(v, want[k]) {
				t.Errorf("%s: obtenu %q, attendu %q", k, v, want[k])
			}
		}
		for k := range want {
			if _, ok := got[k]; !ok {
				t.Errorf("%s non trouvé", k)
			}
		}
		for k := range got {
			if _, ok := want[k]; !ok {
				t.Errorf("fichier inattendu : %s", k)
			}
		}
	}

	all, _ := Scan(root, Options{Dev: true, Indirect: true})
	for _, f := range all {
		switch f.File {
		case "app/package.json":
			if len(f.Terms) != 3 {
				t.Errorf("-dev : %q", f.Terms)
			}
		case "svc/go.mod":
			if len(f.Terms) != 3 {
				t.Errorf("-indirect : %q", f.Terms)
			}
		}
	}
}

// Versions installées : fichiers de verrouillage et versions figées.
func TestScanVersions(t *testing.T) {
	root := t.TempDir()
	// monorepo npm : un seul package-lock.json à la racine, une version
	// imbriquée propre à un espace de travail
	write(t, root, "mono/package.json", `{"dependencies":{"express":"^4.18"}}`)
	write(t, root, "mono/client/package.json", `{"dependencies":{"axios":"^1.6","react":"18.2.0","left-pad":"^1"}}`)
	write(t, root, "mono/package-lock.json", `{"lockfileVersion":3,"packages":{
		"":{}, "node_modules/express":{"version":"4.18.2"}, "node_modules/axios":{"version":"1.7.9"},
		"client/node_modules/axios":{"version":"1.6.0"}}}`)
	write(t, root, "py/pyproject.toml", "[project]\ndependencies = [\"fastapi>=0.110\", \"httpx==0.27.0\", \"Pydantic_Settings\"]\n")
	write(t, root, "py/uv.lock", "version = 1\n\n[[package]]\nname = \"fastapi\"\nversion = \"0.115.6\"\n\n[[package]]\nname = \"pydantic-settings\"\nversion = \"2.7.0\"\n")
	write(t, root, "php/composer.json", `{"require":{"monolog/monolog":"^3","guzzlehttp/guzzle":"7.9.2"}}`)
	write(t, root, "php/composer.lock", `{"packages":[{"name":"monolog/monolog","version":"v3.8.1"}]}`)
	write(t, root, "rs/Cargo.toml", "[dependencies]\nrand = \"0.8\"\nserde = \"1\"\n")
	write(t, root, "rs/Cargo.lock", "[[package]]\nname = \"rand\"\nversion = \"0.7.3\"\n\n[[package]]\nname = \"rand\"\nversion = \"0.8.5\"\n")

	found, err := Scan(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, f := range found {
		got[f.File] = f.Terms
	}
	want := map[string][]string{
		"mono/package.json":        {"npm:express@4.18.2"},
		"mono/client/package.json": {"npm:axios@1.6.0", "npm:left-pad", "npm:react@18.2.0"},
		"py/pyproject.toml":        {"pypi:fastapi@0.115.6", "pypi:httpx@0.27.0", "pypi:pydantic_settings@2.7.0"},
		"php/composer.json":        {"packagist:guzzlehttp/guzzle@7.9.2", "packagist:monolog/monolog@3.8.1"},
		"rs/Cargo.toml":            {"crates:rand@0.7.3,0.8.5", "crates:serde"},
	}
	for k, v := range want {
		if !reflect.DeepEqual(got[k], v) {
			t.Errorf("%s : obtenu %q, attendu %q", k, got[k], v)
		}
	}
}

func TestExactVersion(t *testing.T) {
	for spec, want := range map[string]string{
		"1.2.3": "1.2.3", "=1.2.3": "1.2.3", "v2.0.0-rc.1": "2.0.0-rc.1",
		"^1.2.3": "", "~1.2": "", ">=1.0": "", "*": "", "latest": "", "1.x": "",
	} {
		if got := exactVersion(spec); got != want {
			t.Errorf("exactVersion(%q) = %q, attendu %q", spec, got, want)
		}
	}
}
