package main

import (
	"testing"
	"time"
)

func TestParseSyncInterval(t *testing.T) {
	tests := []struct {
		in       string
		onStart  bool
		duration time.Duration
		wantErr  bool
	}{
		{"onstart", true, 0, false},
		{"", true, 0, false},
		{"ONSTART", true, 0, false},
		{"5m", false, 5 * time.Minute, false},
		{"90s", false, 90 * time.Second, false},
		{"bad", false, 0, true},
		{"0s", false, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			onStart, d, err := parseSyncInterval(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if onStart != tc.onStart || d != tc.duration {
				t.Fatalf("onStart=%v d=%v", onStart, d)
			}
		})
	}
}

func TestSyncRunsEveryCycle(t *testing.T) {
	cfg := &Config{Sync: SyncConfig{Enabled: true, Interval: syncIntervalOnStart}}
	if !cfg.syncRunsEveryCycle(0) {
		t.Fatal("onstart cycle 0")
	}
	if cfg.syncRunsEveryCycle(1) {
		t.Fatal("onstart cycle 1 should skip")
	}
	cfg.Sync.Interval = "5m"
	if !cfg.syncRunsEveryCycle(5) {
		t.Fatal("duration mode every cycle")
	}
	cfg.Sync.Enabled = false
	if cfg.syncRunsEveryCycle(0) {
		t.Fatal("disabled")
	}
}

func TestSyncSleepCap(t *testing.T) {
	cfg := &Config{Sync: SyncConfig{Interval: syncIntervalOnStart}}
	if _, ok := cfg.syncSleepCap(); ok {
		t.Fatal("onstart should not cap sleep")
	}
	cfg.Sync.Interval = "10m"
	cap, ok := cfg.syncSleepCap()
	if !ok || cap != 10*time.Minute {
		t.Fatalf("cap = %v ok = %v", cap, ok)
	}
}

func TestCertProviderListArrayInConfig(t *testing.T) {
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
provider = ["a", "b"]
domains = ["example.com"]
output_dir = "./out"
`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Certificates[0].Providers.names("")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("providers = %v", got)
	}
}
