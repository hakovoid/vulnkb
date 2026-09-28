package versions

import "testing"

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2", "1.2.0", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.10", -1},
		{"1.10.0", "1.9.9", 1},
		{"2.0.0", "10.0.0", -1},
		// semver : pré-versions avant la finale
		{"1.0.0-beta.2", "1.0.0", -1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-rc.1", "1.0.0-beta.11", 1},
		{"1.0.0-rc.1", "1.0.0-rc.2", -1},
		{"5.0.0-0", "5.0.0", -1}, // borne « 5.0.0-0 » des avis npm
		{"1.0.0+build.5", "1.0.0", 0},
		// PEP 440
		{"2.0rc1", "2.0", -1},
		{"2.0.dev1", "2.0a1", -1},
		{"2.0a1", "2.0b1", -1},
		{"2.0.post1", "2.0", 1},
		{"2.0.post1", "2.0.1", -1},
		{"1!1.0", "2.0", 1},
		// Maven
		{"1.0.Final", "1.0", 0},
		{"2.17.1", "2.17.0", 1},
		// Go pseudo-version
		{"0.0.0-20210101000000-abcdef123456", "0.1.0", -1},
	} {
		got, ok := Compare(c.a, c.b)
		if !ok || got != c.want {
			t.Errorf("Compare(%q, %q) = %d, %v ; attendu %d", c.a, c.b, got, ok, c.want)
		}
		if back, _ := Compare(c.b, c.a); back != -c.want {
			t.Errorf("Compare(%q, %q) non antisymétrique : %d", c.b, c.a, back)
		}
	}
	for _, bad := range []string{"", "latest", "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"} {
		if _, ok := Compare(bad, "1.0"); ok {
			t.Errorf("%q devrait être illisible", bad)
		}
	}
}

func TestInRange(t *testing.T) {
	for _, c := range []struct {
		v, intro, fixed, last string
		want                  bool
	}{
		{"1.6.0", "0", "1.6.4", "", true},
		{"1.6.4", "0", "1.6.4", "", false},
		{"1.7.0", "0", "1.6.4", "", false},
		{"0.9.0", "1.0.0", "1.6.4", "", false},
		{"1.0.0", "1.0.0", "1.6.4", "", true},
		{"2.3.0", "2.0.0", "", "2.3.0", true},
		{"2.3.1", "2.0.0", "", "2.3.0", false},
		{"9.9.9", "2.0.0", "", "", true},             // pas encore corrigée
		{"1.0.0", "0", "deadbeefcafe0123", "", true}, // borne illisible : prudence
		{"latest", "0", "1.0.0", "", true},           // version illisible : prudence
	} {
		if got := InRange(c.v, c.intro, c.fixed, c.last); got != c.want {
			t.Errorf("InRange(%q, %q, %q, %q) = %v", c.v, c.intro, c.fixed, c.last, got)
		}
	}
	if !AnyInRange("1.7.2, 1.5.0", "0", "1.6.4", "") || AnyInRange("1.7.2,2.0.0", "0", "1.6.4", "") {
		t.Error("AnyInRange")
	}
}
