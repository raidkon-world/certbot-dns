package main

import "testing"

func TestNormalizeProviderType(t *testing.T) {
	tests := map[string]string{
		"fastdns":       providerTypeFastDNS,
		"fast-dns":      providerTypeFastDNS,
		"alibabacloud":  providerTypeAlibabaCloud,
		"alidns":        providerTypeAlibabaCloud,
		"ali-dns":       providerTypeAlibabaCloud,
		"alicloud":      providerTypeAlibabaCloud,
		"  FastDNS  ":   providerTypeFastDNS,
		"unknown-xyz":   "unknown-xyz",
	}
	for in, want := range tests {
		if got := normalizeProviderType(in); got != want {
			t.Errorf("normalizeProviderType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildProviderRegistryErrors(t *testing.T) {
	cfg := &Config{
		Providers: []ProviderConfig{
			{Name: "dup", Type: "fastdns", APIToken: "a"},
			{Name: "dup", Type: "fastdns", APIToken: "b"},
		},
	}
	if _, err := cfg.buildProviderRegistry(); err == nil {
		t.Fatal("expected duplicate name error")
	}

	cfg = &Config{
		Providers: []ProviderConfig{
			{Name: "x", Type: "fastdns", APIToken: ""},
		},
	}
	if _, err := cfg.buildProviderRegistry(); err == nil {
		t.Fatal("expected empty api_token error")
	}

	cfg = &Config{
		Providers: []ProviderConfig{
			{Name: "ali", Type: "alibabacloud", AccessKeyID: "id", AccessKeySecret: ""},
		},
	}
	if _, err := cfg.buildProviderRegistry(); err == nil {
		t.Fatal("expected empty secret error")
	}

	cfg = &Config{
		Providers: []ProviderConfig{
			{Name: "ali", Type: "alibabacloud", AccessKeyID: "id", AccessKeySecret: "s", SecurityToken: "sts"},
		},
	}
	if _, err := cfg.buildProviderRegistry(); err == nil {
		t.Fatal("expected security_token unsupported error")
	}

	cfg = &Config{
		Providers: []ProviderConfig{{Name: "nope", Type: "cloudflare"}},
	}
	if _, err := cfg.buildProviderRegistry(); err == nil {
		t.Fatal("expected unknown type error")
	}
}

func TestLegacyFastDNSCreatesDefaultProvider(t *testing.T) {
	cfg := &Config{
		FastDNS: FastDNSConfig{APIToken: "tok"},
	}
	reg, err := cfg.buildProviderRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if reg["default"] == nil || reg["default"].providerType != providerTypeFastDNS {
		t.Fatalf("registry = %+v", reg)
	}
	if !reg["default"].sequential || !reg["default"].purgeConflictingTXT {
		t.Fatal("fastdns flags")
	}
}

func TestAlibabaProviderRuntime(t *testing.T) {
	cfg := &Config{
		Providers: []ProviderConfig{
			{Name: "ali", Type: "alibabacloud", AccessKeyID: "id", AccessKeySecret: "sec", RegionID: "cn-hangzhou"},
		},
	}
	reg, err := cfg.buildProviderRegistry()
	if err != nil {
		t.Fatal(err)
	}
	rt := reg["ali"]
	if rt.sequential || rt.purgeConflictingTXT {
		t.Fatal("alibaba should not enable fastdns-specific solver flags")
	}
	if rt.logLabel != "Alibaba Cloud DNS" {
		t.Fatalf("logLabel = %q", rt.logLabel)
	}
}
