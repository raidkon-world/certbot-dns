package main

import (
	"testing"

	"github.com/go-acme/lego/v4/certcrypto"
)

func TestRecordNameForZone(t *testing.T) {
	if recordNameForZone("_acme-challenge.example.com.", "example.com") != "_acme-challenge" {
		t.Fatal()
	}
	if recordNameForZone("example.com.", "example.com") != "example.com" {
		t.Fatal()
	}
}

func TestNormalizeFQDN(t *testing.T) {
	if normalizeFQDN("  foo.bar. ") != "foo.bar" {
		t.Fatal()
	}
}

func TestParseKeyType(t *testing.T) {
	cases := map[string]certcrypto.KeyType{
		"ec256":   certcrypto.EC256,
		"p256":    certcrypto.EC256,
		"rsa4096": certcrypto.RSA4096,
		"4096":    certcrypto.RSA4096,
	}
	for in, want := range cases {
		got, err := parseKeyType(in)
		if err != nil || got != want {
			t.Fatalf("%q: got %v err %v", in, got, err)
		}
	}
	_, err := parseKeyType("invalid-key")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEffectivePropagationResolversDefault(t *testing.T) {
	cfg := &Config{}
	ns := effectivePropagationResolvers(cfg)
	if len(ns) != 2 || ns[0] != "8.8.8.8:53" {
		t.Fatalf("default resolvers = %v", ns)
	}
}

func TestBuildDNSOpts(t *testing.T) {
	cfg := &Config{DNSChallenge: DNSChallengeConfig{RecursiveResolvers: []string{"1.1.1.1:53"}}}
	opts, err := buildDNSOpts(cfg)
	if err != nil || len(opts) == 0 {
		t.Fatalf("opts = %v err = %v", opts, err)
	}
}

func TestCertLabel(t *testing.T) {
	if certLabel(CertConfig{ID: "sites"}, 0) != "sites" {
		t.Fatal()
	}
	if certLabel(CertConfig{}, 3) != "#3" {
		t.Fatal()
	}
}
