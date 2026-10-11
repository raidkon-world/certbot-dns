package main

import (
	"testing"
	"time"
)

func TestCheckpointKeyForProvider(t *testing.T) {
	k := checkpointKeyForProvider("a.example.com", "fv")
	if k != "a.example.com|fv" {
		t.Fatalf("key = %q", k)
	}
}

func TestDNSolverGroupRestoreTXTRecordIDs(t *testing.T) {
	reg := map[string]*providerRuntime{
		"a": {name: "a", logLabel: "A", client: &mockDNSClient{}, sequential: true, purgeConflictingTXT: true},
		"b": {name: "b", logLabel: "B", client: &mockDNSClient{}},
	}
	g, err := newDNSSolverGroup(reg, []string{"a", "b"}, "example.com", time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	from := map[string]string{
		"fqdn|a": "id-a",
		"fqdn|b": "id-b",
		"legacy": "id-legacy",
	}
	g.restoreTXTRecordIDs(from)
	if g.items[0].ids["fqdn"] != "id-a" {
		t.Fatalf("a ids = %v", g.items[0].ids)
	}
	if g.items[1].ids["fqdn"] != "id-b" {
		t.Fatalf("b ids = %v", g.items[1].ids)
	}

	gSingle, err := newDNSSolverGroup(map[string]*providerRuntime{"a": reg["a"]}, []string{"a"}, "example.com", time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	gSingle.restoreTXTRecordIDs(map[string]string{"fqdn": "legacy-id"})
	if gSingle.items[0].ids["fqdn"] != "legacy-id" {
		t.Fatalf("legacy restore = %v", gSingle.items[0].ids)
	}
}

func TestNewDNSSolverGroupUnknownProvider(t *testing.T) {
	_, err := newDNSSolverGroup(map[string]*providerRuntime{}, []string{"nope"}, "example.com", time.Minute, time.Minute)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDNSolverGroupSequentialUsesMax(t *testing.T) {
	reg := map[string]*providerRuntime{
		"a": {name: "a", logLabel: "A", client: &mockDNSClient{}, sequential: true},
		"b": {name: "b", logLabel: "B", client: &mockDNSClient{}},
	}
	g, err := newDNSSolverGroup(reg, []string{"a", "b"}, "example.com", 2*time.Hour, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if g.Sequential() != 30*time.Second {
		t.Fatalf("sequential = %v", g.Sequential())
	}
	to, iv := g.Timeout()
	if to != 2*time.Hour || iv != 30*time.Second {
		t.Fatalf("timeout = %v interval = %v", to, iv)
	}
}
