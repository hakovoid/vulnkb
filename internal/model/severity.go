package model

import (
	"fmt"
	"math"
	"strings"
)

// Niveaux de sévérité communs à toutes les sources.
const (
	SevUnknown = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

// Severity est une gravité ramenée à une échelle commune, quelle que soit la
// façon dont la source l'exprime (libellé, vecteur CVSS…).
type Severity struct {
	Level int    // SevUnknown … SevCritical
	Score string // score CVSS calculé, si la source ne donne qu'un vecteur
}

var sevLevels = map[string]int{"CRITICAL": SevCritical, "HIGH": SevHigh, "MODERATE": SevMedium, "MEDIUM": SevMedium, "LOW": SevLow}

// ParseSeverity interprète la sévérité brute d'une source.
func ParseSeverity(raw string) Severity {
	raw = strings.TrimSpace(raw)
	if l, ok := sevLevels[strings.ToUpper(raw)]; ok {
		return Severity{Level: l}
	}
	if score, ok := CVSS3Score(raw); ok {
		return Severity{Level: levelForScore(score), Score: fmt.Sprintf("%.1f", score)}
	}
	return Severity{}
}

func levelForScore(s float64) int {
	switch {
	case s >= 9:
		return SevCritical
	case s >= 7:
		return SevHigh
	case s >= 4:
		return SevMedium
	case s > 0:
		return SevLow
	}
	return SevUnknown
}

// CVSS3Score calcule le score de base d'un vecteur CVSS 3.0/3.1
// (spécification FIRST, section 7).
func CVSS3Score(vector string) (float64, bool) {
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return 0, false
	}
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}
	changed := m["S"] == "C"
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	ac := map[string]float64{"L": 0.77, "H": 0.44}
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		pr["L"], pr["H"] = 0.68, 0.5
	}
	ui := map[string]float64{"N": 0.85, "R": 0.62}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

	vals := make([]float64, 0, 7)
	for _, p := range []struct {
		tbl map[string]float64
		key string
	}{{av, "AV"}, {ac, "AC"}, {pr, "PR"}, {ui, "UI"}, {cia, "C"}, {cia, "I"}, {cia, "A"}} {
		v, ok := p.tbl[m[p.key]]
		if !ok {
			return 0, false
		}
		vals = append(vals, v)
	}

	iss := 1 - (1-vals[4])*(1-vals[5])*(1-vals[6])
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}
	expl := 8.22 * vals[0] * vals[1] * vals[2] * vals[3]
	if changed {
		return roundUp(math.Min(1.08*(impact+expl), 10)), true
	}
	return roundUp(math.Min(impact+expl, 10)), true
}

// roundUp est l'arrondi supérieur à une décimale défini par CVSS 3.1.
func roundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}
