package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestRecordNameExcluded(t *testing.T) {
	patterns := []string{"_acme-challenge", "_acme-challenge.*"}
	if !recordNameExcluded("_acme-challenge", patterns) {
		t.Fatal("exact")
	}
	if !recordNameExcluded("_acme-challenge.foo", patterns) {
		t.Fatal("suffix")
	}
	if recordNameExcluded("www", patterns) {
		t.Fatal("www should not match")
	}
}

func TestFilterSyncRecords(t *testing.T) {
	types := map[string]struct{}{"A": {}, "TXT": {}}
	exclude := []string{"_acme-challenge"}
	recs := []libdns.Record{
		{Name: "www", Type: "a", Value: "1.2.3.4"},
		{Name: "_acme-challenge", Type: "TXT", Value: "x"},
		{Name: "mail", Type: "MX", Value: "mx.example.com", Priority: 10},
		{Name: "www.example.com", Type: "A", Value: "1.2.3.5"},
	}
	out := filterSyncRecords(recs, "example.com", types, exclude)
	if len(out) != 2 {
		t.Fatalf("len = %d, recs = %+v", len(out), out)
	}
	if out[0].Name != "www" || out[1].Name != "www" {
		t.Fatalf("normalized names = %q, %q", out[0].Name, out[1].Name)
	}
}

func TestSyncRecordKey(t *testing.T) {
	k1 := syncRecordKey(libdns.Record{Name: "www", Type: "A", Value: "1"})
	k2 := syncRecordKey(libdns.Record{Name: "www", Type: "A", Value: "2"})
	if k1 == k2 {
		t.Fatal("different values should differ")
	}
	k3 := syncRecordKey(libdns.Record{Name: "www", Type: "MX", Value: "mx", Priority: 10})
	k4 := syncRecordKey(libdns.Record{Name: "www", Type: "MX", Value: "mx", Priority: 20})
	if k3 == k4 {
		t.Fatal("priority matters for MX")
	}
}

func TestResolveSyncMasterSource(t *testing.T) {
	reg := map[string]*providerRuntime{
		"fv": {name: "fv", logLabel: "FastDNS"},
	}
	src, err := resolveSyncMasterSource("fv", reg)
	if err != nil {
		t.Fatal(err)
	}
	if src.label() != "fv" {
		t.Fatalf("label = %q", src.label())
	}
	zonePath := writeTestZoneFile(t, "z.zone", `$ORIGIN example.com.
@ 3600 IN A 1.2.3.4
`)
	src, err = resolveSyncMasterSource("file://"+zonePath, reg)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := src.getRecords(context.Background(), "example.com")
	if err != nil || len(recs) != 1 {
		t.Fatalf("recs err=%v len=%d", err, len(recs))
	}
	_, err = resolveSyncMasterSource("missing", reg)
	if err == nil {
		t.Fatal("expected unknown master")
	}
}

func TestParseFileMasterPathVariants(t *testing.T) {
	p, err := parseFileMasterPath("file:///etc/zone/example.com.zone")
	if err != nil || p != filepath.Clean("/etc/zone/example.com.zone") {
		t.Fatalf("path = %q err = %v", p, err)
	}
	if !isFileMasterRef("file:///x") {
		t.Fatal()
	}
	if isFileMasterRef("fv-main") {
		t.Fatal()
	}
	_, err = parseFileMasterPath("http://example.com")
	if err == nil {
		t.Fatal("expected error for non-file")
	}
}

type mockDNSClient struct {
	records []libdns.Record
	set     []libdns.Record
}

func (m *mockDNSClient) GetRecords(_ context.Context, _ string) ([]libdns.Record, error) {
	return append([]libdns.Record(nil), m.records...), nil
}

func (m *mockDNSClient) AppendRecords(_ context.Context, _ string, recs []libdns.Record) ([]libdns.Record, error) {
	return recs, nil
}

func (m *mockDNSClient) DeleteRecords(_ context.Context, _ string, recs []libdns.Record) ([]libdns.Record, error) {
	return recs, nil
}

func (m *mockDNSClient) SetRecords(_ context.Context, _ string, recs []libdns.Record) ([]libdns.Record, error) {
	m.set = append([]libdns.Record(nil), recs...)
	return recs, nil
}

func TestSyncZoneToProviderPreservesExcluded(t *testing.T) {
	client := &mockDNSClient{
		records: []libdns.Record{
			{ID: "1", Name: "www", Type: "A", Value: "9.9.9.9", TTL: time.Hour},
			{ID: "2", Name: "_acme-challenge", Type: "TXT", Value: "keep-me", TTL: time.Hour},
		},
	}
	slave := &providerRuntime{name: "fv", logLabel: "mock", client: client}
	desired := []libdns.Record{
		{Name: "www", Type: "A", Value: "1.2.3.4", TTL: time.Hour},
	}
	exclude := []string{"_acme-challenge", "_acme-challenge.*"}
	types := map[string]struct{}{"A": {}, "TXT": {}}
	err := syncZoneToProvider(context.Background(), "example.com", desired, exclude, types, slave, "fv")
	if err != nil {
		t.Fatal(err)
	}
	if len(client.set) != 2 {
		t.Fatalf("set len = %d, want master + preserved TXT", len(client.set))
	}
	var hasTXT bool
	for _, r := range client.set {
		if r.Name == "_acme-challenge" && r.Value == "keep-me" {
			hasTXT = true
		}
	}
	if !hasTXT {
		t.Fatalf("set = %+v", client.set)
	}
}

func TestRunDNSSyncFromZoneFile(t *testing.T) {
	zonePath := writeTestZoneFile(t, "example.com.zone", `$ORIGIN example.com.
www 3600 IN A 203.0.113.10
_acme-challenge 3600 IN TXT "skip"
`)
	client := &mockDNSClient{}
	cfg := &Config{
		Sync: SyncConfig{
			Enabled: true,
			Zones: []SyncZoneConfig{{
				Zone:   "example.com",
				Master: fileMasterPrefix + zonePath,
				Slaves: []string{"fv"},
			}},
		},
	}
	reg := map[string]*providerRuntime{
		"fv": {name: "fv", logLabel: "mock", client: client},
	}
	if err := runDNSSync(context.Background(), cfg, reg); err != nil {
		t.Fatal(err)
	}
	if len(client.set) != 1 || client.set[0].Name != "www" {
		t.Fatalf("set = %+v", client.set)
	}
}
