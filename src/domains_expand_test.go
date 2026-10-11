package main

import (
	"path/filepath"
	"slices"
	"testing"
)

func testRegistry(t *testing.T) map[string]*providerRuntime {
	t.Helper()
	cfg := &Config{
		Providers: []ProviderConfig{{Name: "fv", Type: "fastdns", APIToken: "t"}},
	}
	reg, err := cfg.buildProviderRegistry()
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestExpandWildcardAddsApex(t *testing.T) {
	reg := testRegistry(t)
	entry := CertConfig{
		ProviderRaw: "fv",
		Domains:     []string{"*.example.com"},
		OutputDir:   "./out/sites",
		KeyType:     "ec256",
	}
	entry.Providers = certProviderList{"fv"}
	out, err := expandCertEntry(entry, 0, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("len = %d", len(out))
	}
	if !slices.Contains(out[0].Domains, "*.example.com") || !slices.Contains(out[0].Domains, "example.com") {
		t.Fatalf("domains = %v", out[0].Domains)
	}
	if out[0].Zone != "example.com" {
		t.Fatalf("zone = %q", out[0].Zone)
	}
	if out[0].OutputDir != filepath.Join("./out/sites", "wc-example-com") {
		t.Fatalf("output = %q", out[0].OutputDir)
	}
	if len(out[0].Providers) != 1 || out[0].Providers[0] != "fv" {
		t.Fatalf("providers = %v", out[0].Providers)
	}
}

func TestExpandMultipleWildcards(t *testing.T) {
	reg := testRegistry(t)
	entry := CertConfig{
		Providers: certProviderList{"fv"},
		Domains:   []string{"*.example.com", "*.demo.com"},
		OutputDir: "./out",
		KeyType:   "ec256",
	}
	out, err := expandCertEntry(entry, 0, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("len = %d", len(out))
	}
}

func TestExpandApexOnly(t *testing.T) {
	reg := testRegistry(t)
	entry := CertConfig{
		Providers: certProviderList{"fv"},
		Domains:   []string{"orphan.net"},
		OutputDir: "./out",
		KeyType:   "ec256",
	}
	out, err := expandCertEntry(entry, 0, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].OutputDir != filepath.Join("./out", "apex-orphan-net") {
		t.Fatalf("out = %+v", out)
	}
}

func TestExpandOneLabelUnderWildcard(t *testing.T) {
	reg := testRegistry(t)
	entry := CertConfig{
		Providers: certProviderList{"fv"},
		Domains:   []string{"*.example.com", "www.example.com"},
		OutputDir: "./out",
		KeyType:   "ec256",
	}
	out, err := expandCertEntry(entry, 0, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("len = %d", len(out))
	}
	if !slices.Contains(out[0].Domains, "www.example.com") {
		t.Fatalf("domains = %v", out[0].Domains)
	}
}

func TestExpandDomainErrors(t *testing.T) {
	reg := testRegistry(t)
	_, err := expandCertEntry(CertConfig{Domains: []string{"*."}}, 0, reg)
	if err == nil {
		t.Fatal("expected error for empty wildcard apex")
	}
	_, err = expandCertEntry(CertConfig{Domains: []string{"*invalid.com"}}, 0, reg)
	if err == nil {
		t.Fatal("expected error for star without dot")
	}
}

func TestFastDNSRootZone(t *testing.T) {
	if fastDNSRootZone("www.example.com") != "example.com" {
		t.Fatal()
	}
	if fastDNSRootZone("example.com") != "example.com" {
		t.Fatal()
	}
}

func TestUnderOneLabelSubdomain(t *testing.T) {
	if !underOneLabelSubdomain("api.p1.example.org", "p1.example.org") {
		t.Fatal()
	}
	if underOneLabelSubdomain("deep.api.p1.example.org", "p1.example.org") {
		t.Fatal()
	}
}

func TestExpandMultiProviderPreserved(t *testing.T) {
	reg := testRegistry(t)
	entry := CertConfig{
		Providers: certProviderList{"fv", "fv"},
		Domains:   []string{"example.com"},
		OutputDir: "./out",
		KeyType:   "ec256",
	}
	out, err := expandCertEntry(entry, 0, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(out[0].Providers) != 1 {
		t.Fatalf("dedupe providers in entry: %v", out[0].Providers)
	}
}
