package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigLegacyFastDNS(t *testing.T) {
	path := writeTestConfig(t, `
[acme]
email = "a@b.com"
directory = "staging"
state_dir = ".state"

[fastdns]
api_token = "tok"

[[certificates]]
domains = ["*.example.com"]
output_dir = "./out"
`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := cfg.buildProviderRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if reg["default"] == nil {
		t.Fatal("expected default provider from [fastdns]")
	}
	names := cfg.Certificates[0].Providers.names(defaultProviderName)
	if len(names) != 1 || names[0] != defaultProviderName {
		t.Fatalf("provider = %v, want [%s]", names, defaultProviderName)
	}
	if cfg.ACME.Directory != "staging" || cfg.ACME.StateDir != ".state" {
		t.Fatalf("acme = %+v", cfg.ACME)
	}
}

func TestLoadConfigNamedProviders(t *testing.T) {
	path := writeTestConfig(t, `
[acme]
email = "a@b.com"

[[providers]]
name = "fv"
type = "fastdns"
api_token = "tok"

[[providers]]
name = "ali"
type = "alibabacloud"
access_key_id = "id"
access_key_secret = "secret"

[[certificates]]
provider = "ali"
domains = ["example.com"]
output_dir = "./out"
`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := cfg.buildProviderRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if reg["ali"].providerType != providerTypeAlibabaCloud {
		t.Fatalf("type = %q", reg["ali"].providerType)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	path := writeTestConfig(t, minimalConfig(""))
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sync.Interval != syncIntervalOnStart {
		t.Fatalf("sync.interval = %q", cfg.Sync.Interval)
	}
	if cfg.DNSChallenge.PropagationTimeout != "24h" {
		t.Fatalf("propagation_timeout = %q", cfg.DNSChallenge.PropagationTimeout)
	}
	if cfg.Runtime.Mode != "once" {
		t.Fatalf("mode = %q", cfg.Runtime.Mode)
	}
	if cfg.Certificates[0].RenewBeforeDays != 25 || cfg.Certificates[0].KeyType != "ec256" {
		t.Fatalf("cert defaults = %+v", cfg.Certificates[0])
	}
}

func TestLoadConfigEnvExpansion(t *testing.T) {
	t.Setenv("TEST_FASTDNS_TOKEN", "from-env")
	t.Setenv("TEST_OUT", "/tmp/certs-test")
	path := writeTestConfig(t, `
[acme]
email = "a@b.com"

[[providers]]
name = "fv"
type = "fastdns"
api_token = "${TEST_FASTDNS_TOKEN}"

[[certificates]]
provider = "fv"
domains = ["example.com"]
output_dir = "${TEST_OUT}"
`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := cfg.buildProviderRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if reg["fv"].client == nil {
		t.Fatal("no client")
	}
	if cfg.Certificates[0].OutputDir != "/tmp/certs-test" {
		t.Fatalf("output_dir = %q", cfg.Certificates[0].OutputDir)
	}
}

func TestLoadConfigValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
		contains string
	}{
		{
			name: "no email",
			body: `
[[providers]]
name = "fv"
type = "fastdns"
api_token = "t"
[[certificates]]
provider = "fv"
domains = ["example.com"]
output_dir = "./out"
`,
			contains: "acme.email",
		},
		{
			name: "bad directory",
			body: `
[acme]
email = "a@b.com"
directory = "invalid"
[[providers]]
name = "fv"
type = "fastdns"
api_token = "t"
[[certificates]]
provider = "fv"
domains = ["example.com"]
output_dir = "./out"
`,
			contains: "acme.directory",
		},
		{
			name: "unknown cert provider",
			body: `
[acme]
email = "a@b.com"
[[providers]]
name = "fv"
type = "fastdns"
api_token = "t"
[[certificates]]
provider = "missing"
domains = ["example.com"]
output_dir = "./out"
`,
			contains: "неизвестный провайдер",
		},
		{
			name: "empty domains",
			body: `
[acme]
email = "a@b.com"
[[providers]]
name = "fv"
type = "fastdns"
api_token = "t"
[[certificates]]
provider = "fv"
domains = []
output_dir = "./out"
`,
			contains: "domains",
		},
		{
			name: "bad runtime mode",
			body: minimalConfig(`
[runtime]
mode = "continuous"
`),
			contains: "runtime.mode",
		},
		{
			name: "bad key type",
			body: `
[acme]
email = "a@b.com"
[[providers]]
name = "fv"
type = "fastdns"
api_token = "t"
[[certificates]]
provider = "fv"
domains = ["example.com"]
output_dir = "./out"
key_type = "ed25519"
`,
			contains: "key_type",
		},
		{
			name: "sync enabled no zones",
			body: minimalConfig(`
[sync]
enabled = true
interval = "onstart"
`),
			contains: "sync.zones",
		},
		{
			name: "sync bad interval",
			body: minimalConfig(`
[sync]
enabled = true
interval = "not-a-duration"
[[sync.zones]]
zone = "example.com"
master = "fv"
slaves = ["fv"]
`),
			contains: "sync.interval",
		},
		{
			name: "sync unknown slave",
			body: minimalConfig(`
[sync]
enabled = true
[[sync.zones]]
zone = "example.com"
master = "fv"
slaves = ["ghost"]
`),
			contains: "slaves",
		},
		{
			name: "no providers",
			body: `
[acme]
email = "a@b.com"
[[certificates]]
domains = ["example.com"]
output_dir = "./out"
`,
			contains: "providers",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTestConfig(t, tc.body)
			_, err := loadConfig(path)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("error %q should contain %q", err.Error(), tc.contains)
			}
		})
	}
}

func TestLoadConfigSyncFileMaster(t *testing.T) {
	zonePath := writeTestZoneFile(t, "example.com.zone", `$TTL 3600
$ORIGIN example.com.
www 3600 IN A 203.0.113.1
`)
	path := writeTestConfig(t, minimalConfig(`
[sync]
enabled = true
interval = "5m"
[[sync.zones]]
zone = "example.com"
master = "file://`+zonePath+`"
slaves = ["fv"]
`))
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Sync.Enabled || len(cfg.Sync.Zones) != 1 {
		t.Fatalf("sync = %+v", cfg.Sync)
	}
}

func TestLoadConfigSyncFileMasterOriginMismatch(t *testing.T) {
	zonePath := writeTestZoneFile(t, "bad.zone", `$ORIGIN other.com.
@ 3600 IN A 1.2.3.4
`)
	path := writeTestConfig(t, minimalConfig(`
[sync]
enabled = true
[[sync.zones]]
zone = "example.com"
master = "file://`+zonePath+`"
slaves = ["fv"]
`))
	_, err := loadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "$ORIGIN") {
		t.Fatalf("expected ORIGIN mismatch, got %v", err)
	}
}

func TestLoadConfigSyncCustomExcludeAndRecordTypes(t *testing.T) {
	path := writeTestConfig(t, minimalConfig(`
[sync]
enabled = false
record_types = ["A", "TXT"]
exclude_names = ["_acme-challenge*"]
`))
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	types := cfg.syncRecordTypes()
	if _, ok := types["A"]; !ok {
		t.Fatalf("types = %v", types)
	}
	if _, ok := types["MX"]; ok {
		t.Fatalf("MX should not be in custom types: %v", types)
	}
	ex := cfg.syncExcludePatterns()
	if len(ex) != 1 || ex[0] != "_acme-challenge*" {
		t.Fatalf("exclude = %v", ex)
	}
}

func TestLoadConfigMultiCertificateBlocks(t *testing.T) {
	path := writeTestConfig(t, `
[acme]
email = "a@b.com"
[[providers]]
name = "fv"
type = "fastdns"
api_token = "t"
[[certificates]]
id = "sites"
provider = ["fv"]
domains = ["*.example.com"]
output_dir = "./out/a"
[[certificates]]
id = "shop"
provider = "fv"
domains = ["shop.example.net"]
output_dir = "./out/b"
`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := cfg.buildProviderRegistry()
	expanded, err := expandAllCerts(cfg.Certificates, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(expanded) < 2 {
		t.Fatalf("expanded = %d", len(expanded))
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := loadConfig(filepath.Join(t.TempDir(), "missing.toml"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadConfigProviderArrayInToml(t *testing.T) {
	path := writeTestConfig(t, `
[acme]
email = "a@b.com"
[[providers]]
name = "a"
type = "fastdns"
api_token = "t"
[[providers]]
name = "b"
type = "fastdns"
api_token = "t2"
[[certificates]]
provider = ["a", "b", "a"]
domains = ["example.com"]
output_dir = "./out"
`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Certificates[0].Providers.names("")
	if len(got) != 2 {
		t.Fatalf("providers = %v", got)
	}
}

func TestLoadConfigLoggingLevels(t *testing.T) {
	for _, lvl := range []string{"debug", "verbose", "info", "warning", "error", "fatal"} {
		path := writeTestConfig(t, minimalConfig(`
[runtime]
loglevel = "`+lvl+`"
`))
		if _, err := loadConfig(path); err != nil {
			t.Fatalf("level %q: %v", lvl, err)
		}
	}
	path := writeTestConfig(t, minimalConfig(`
[runtime]
loglevel = "trace"
`))
	if _, err := loadConfig(path); err == nil {
		t.Fatal("expected bad loglevel error")
	}
}

func TestLoadConfigRecursiveResolvers(t *testing.T) {
	path := writeTestConfig(t, minimalConfig(`
[dns_challenge]
recursive_resolvers = ["9.9.9.9:53", "8.8.8.8:53"]
`))
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	ns := effectivePropagationResolvers(cfg)
	if len(ns) != 2 || ns[0] != "9.9.9.9:53" {
		t.Fatalf("resolvers = %v", ns)
	}
}

func TestLoadConfigStagingDirectory(t *testing.T) {
	path := writeTestConfig(t, `
[acme]
email = "a@b.com"
directory = "staging"
[[providers]]
name = "fv"
type = "fastdns"
api_token = "t"
[[certificates]]
provider = "fv"
domains = ["example.com"]
output_dir = "./out"
`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ACME.Directory != "staging" {
		t.Fatal()
	}
}

func TestConfigFilePermissionsReadable(t *testing.T) {
	path := writeTestConfig(t, minimalConfig(""))
	if _, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	}
}
