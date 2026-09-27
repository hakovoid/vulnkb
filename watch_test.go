package main

import (
	"reflect"
	"testing"
)

func TestWatchFileEdits(t *testing.T) {
	lines := []string{"# en-tête", "nginx", "", "# koai/package.json", "npm:express"}
	lines, n := appendTerms(lines, []string{"NGINX", "vtiger", "vtiger", " "}, "# ajout")
	if n != 1 || lines[len(lines)-1] != "vtiger" || lines[len(lines)-2] != "# ajout" {
		t.Errorf("appendTerms: %d, %q", n, lines)
	}
	lines = removeTerms(lines, []string{"Npm:Express"})
	if got := termsOf(lines); !reflect.DeepEqual(got, []string{"nginx", "vtiger"}) {
		t.Errorf("après retrait: %q", got)
	}
	if lines[3] != "# koai/package.json" {
		t.Errorf("commentaire perdu: %q", lines)
	}
}
