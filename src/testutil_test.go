package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTestZoneFile(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func minimalConfig(extra string) string {
	base := `
[acme]
email = "admin@example.com"
directory = "production"

[[providers]]
name = "fv"
type = "fastdns"
api_token = "tok"

[[certificates]]
provider = "fv"
domains = ["example.com"]
output_dir = "./out"
`
	return base + extra
}
