package epss

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	in := "#model_version:v2026.06.15,score_date:2026-09-27T12:00:21Z\ncve,epss,percentile\nCVE-1999-0001,0.03351,0.88245\nCVE-2021-44228,0.99999,1.00000\nligne invalide\nCVE-2026-1,abc,0.1\n"
	scores, date, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(scores) != 2 || scores[1] != (Score{"CVE-2021-44228", 0.99999, 1}) {
		t.Errorf("scores: %+v", scores)
	}
	if date.Format("2006-01-02") != "2026-09-27" {
		t.Errorf("date: %v", date)
	}
	if _, _, err := Parse(strings.NewReader("cve,epss,percentile\n")); err == nil {
		t.Error("fichier vide accepté")
	}
}
