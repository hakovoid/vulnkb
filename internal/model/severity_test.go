package model

import "testing"

func TestCVSS3Score(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N": 3.7,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for v, want := range cases {
		got, ok := CVSS3Score(v)
		if !ok || got != want {
			t.Errorf("%s: obtenu %.1f (%v), attendu %.1f", v, got, ok, want)
		}
	}
	for _, bad := range []string{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N", "CVSS:3.1/AV:X/AC:L", "HIGH", ""} {
		if _, ok := CVSS3Score(bad); ok {
			t.Errorf("%q: vecteur invalide accepté", bad)
		}
	}
}
