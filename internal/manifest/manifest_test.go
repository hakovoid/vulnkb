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
		"svc/go.mod":          {"go:github.com/spf13/cobra", "go:gopkg.in/yaml.v3"},
		"py/requirements.txt": {"pypi:fastapi", "pypi:pillow", "pypi:uvicorn"},
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
