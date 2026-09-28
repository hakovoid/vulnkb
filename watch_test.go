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

func TestWatchVersions(t *testing.T) {
	lines := []string{"npm:axios@1.6.0", "npm:@scope/pkg@2.0.0", "redis"}
	// même paquet, nouvelle version : la ligne est remplacée
	lines, n := appendTerms(lines, []string{"npm:axios@1.7.9", "npm:@scope/pkg"}, "")
	if n != 0 || lines[0] != "npm:axios@1.7.9" || lines[1] != "npm:@scope/pkg" {
		t.Errorf("remplacement : %d, %q", n, lines)
	}
	// le retrait ignore la version
	lines = removeTerms(lines, []string{"npm:Axios", "npm:@scope/pkg@9"})
	if got := termsOf(lines); !reflect.DeepEqual(got, []string{"redis"}) {
		t.Errorf("retrait : %q", got)
	}
}
