package source

import (
	"reflect"
	"testing"
)

func TestNoteRefs(t *testing.T) {
	nvd := "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"
	notes := "https://vendor.example/advisory/123 ; https://github.com/org/repo/commit/abc. ; " + nvd
	got := noteRefs(nvd, notes)
	want := []string{
		nvd,
		"https://vendor.example/advisory/123",
		"https://github.com/org/repo/commit/abc",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("noteRefs:\n got  %q\n want %q", got, want)
	}

	if got := noteRefs(nvd, ""); !reflect.DeepEqual(got, []string{nvd}) {
		t.Errorf("notes vides: %q", got)
	}
}
