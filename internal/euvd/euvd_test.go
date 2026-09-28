package euvd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func init() { Pause, Backoff = 0, []time.Duration{0, 0} }

func TestFetch(t *testing.T) {
	// 230 fiches, servies par pages de 100 ; une sur dix exploitée
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		var items []map[string]string
		for i := page * 100; i < min(230, (page+1)*100); i++ {
			it := map[string]string{"id": fmt.Sprintf("EUVD-2026-%d", i), "aliases": fmt.Sprintf("CVE-2026-%d\nGHSA-x\n", 10000+i)}
			if i%10 == 0 {
				it["exploitedSince"] = "Sep 27, 2026, 12:00:00 AM"
			}
			items = append(items, it)
		}
		json.NewEncoder(w).Encode(map[string]any{"items": items, "total": 230})
	}))
	defer srv.Close()

	var got []Record
	err := Fetch(context.Background(), srv.Client(), srv.URL, Query{Exploited: true}, func(r Record) error {
		got = append(got, r)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 230 || len(queries) != 3 {
		t.Fatalf("%d fiches en %d pages", len(got), len(queries))
	}
	if queries[0] != "exploited=true&page=0&size=100" {
		t.Errorf("paramètres : %s", queries[0])
	}
	r := got[10]
	if r.ID != "EUVD-2026-10" || len(r.CVEs) != 1 || r.CVEs[0] != "CVE-2026-10010" || r.ExploitedSince.Format("2006-01-02") != "2026-09-27" {
		t.Errorf("fiche : %+v", r)
	}
	if !got[11].ExploitedSince.IsZero() {
		t.Error("fiche non exploitée marquée exploitée")
	}
}

func TestIsID(t *testing.T) {
	for s, want := range map[string]bool{"EUVD-2026-72027": true, "euvd-2025-1": true, "EUVD-26-1": false, "CVE-2026-1234": false} {
		if IsID(s) != want {
			t.Errorf("IsID(%q) != %v", s, want)
		}
	}
}

func TestFetchThrottled(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls <= 2 { // limité deux fois, puis servi
			w.WriteHeader(http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"items": []map[string]string{{"id": "EUVD-2026-1", "aliases": "CVE-2026-1111"}}, "total": 1})
	}))
	defer srv.Close()
	n := 0
	err := Fetch(context.Background(), srv.Client(), srv.URL, Query{}, func(Record) error { n++; return nil })
	if err != nil || n != 1 || calls != 3 {
		t.Errorf("après limitation : %v, %d fiches, %d appels", err, n, calls)
	}
}
