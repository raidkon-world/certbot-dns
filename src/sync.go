package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/libdns/libdns"
)

type zoneRecordSource interface {
	label() string
	getRecords(ctx context.Context, zone string) ([]libdns.Record, error)
}

type fileZoneSource struct {
	path string
}

func (f fileZoneSource) label() string { return "file://" + f.path }

func (f fileZoneSource) getRecords(_ context.Context, zone string) ([]libdns.Record, error) {
	return loadRecordsFromZoneFile(f.path, zone)
}

type providerZoneSource struct {
	name string
	pr   *providerRuntime
}

func (p providerZoneSource) label() string { return p.name }

func (p providerZoneSource) getRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	recs, err := dnsRetryWithValue(p.pr.logLabel, "GetRecords(sync)", func() ([]libdns.Record, error) {
		return p.pr.client.GetRecords(ctx, zone)
	})
	if err != nil {
		return nil, err
	}
	for i := range recs {
		recs[i].Name = normalizeZoneRecordName(recs[i].Name, zone)
	}
	return recs, nil
}

func resolveSyncMasterSource(master string, registry map[string]*providerRuntime) (zoneRecordSource, error) {
	if isFileMasterRef(master) {
		path, err := parseFileMasterPath(master)
		if err != nil {
			return nil, err
		}
		return fileZoneSource{path: path}, nil
	}
	pr, ok := registry[master]
	if !ok {
		return nil, fmt.Errorf("неизвестный master %q (имя [[providers]] или file://…)", master)
	}
	return providerZoneSource{name: master, pr: pr}, nil
}

func (c *Config) syncExcludePatterns() []string {
	if len(c.Sync.ExcludeNames) > 0 {
		return c.Sync.ExcludeNames
	}
	return []string{"_acme-challenge", "_acme-challenge.*"}
}

func (c *Config) syncRecordTypes() map[string]struct{} {
	if len(c.Sync.RecordTypes) == 0 {
		return map[string]struct{}{
			"A": {}, "AAAA": {}, "CNAME": {}, "MX": {}, "TXT": {}, "NS": {}, "SRV": {},
		}
	}
	m := make(map[string]struct{}, len(c.Sync.RecordTypes))
	for _, t := range c.Sync.RecordTypes {
		t = strings.ToUpper(strings.TrimSpace(t))
		if t != "" {
			m[t] = struct{}{}
		}
	}
	return m
}

func recordNameExcluded(name string, patterns []string) bool {
	name = strings.TrimSpace(name)
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if ok, _ := filepath.Match(p, name); ok {
			return true
		}
	}
	return false
}

func filterSyncRecords(recs []libdns.Record, zone string, types map[string]struct{}, exclude []string) []libdns.Record {
	var out []libdns.Record
	for _, r := range recs {
		typ := strings.ToUpper(strings.TrimSpace(r.Type))
		if _, ok := types[typ]; !ok {
			continue
		}
		name := normalizeZoneRecordName(r.Name, zone)
		if recordNameExcluded(name, exclude) {
			continue
		}
		r.Name = name
		r.Type = typ
		out = append(out, r)
	}
	return out
}

type syncRecKey struct {
	name     string
	typ      string
	value    string
	priority int
}

func syncRecordKey(r libdns.Record) syncRecKey {
	return syncRecKey{
		name:     normalizeZoneRecordName(r.Name, ""),
		typ:      strings.ToUpper(strings.TrimSpace(r.Type)),
		value:    strings.TrimSpace(r.Value),
		priority: r.Priority,
	}
}

func runDNSSync(ctx context.Context, cfg *Config, registry map[string]*providerRuntime) error {
	types := cfg.syncRecordTypes()
	exclude := cfg.syncExcludePatterns()
	for i := range cfg.Sync.Zones {
		z := &cfg.Sync.Zones[i]
		zone := normalizeZoneName(z.Zone)
		if zone == "" {
			continue
		}
		master, err := resolveSyncMasterSource(z.Master, registry)
		if err != nil {
			return fmt.Errorf("sync.zones[%d]: %w", i, err)
		}
		desired, err := master.getRecords(ctx, zone)
		if err != nil {
			return fmt.Errorf("sync zone %q master %s: %w", zone, master.label(), err)
		}
		desired = filterSyncRecords(desired, zone, types, exclude)
		slog.Info("sync: прочитан master", "zone", zone, "master", master.label(), "records", len(desired))

		for _, slaveName := range z.Slaves {
			slave := registry[slaveName]
			if slave == nil {
				return fmt.Errorf("sync zone %q: неизвестный slave %q", zone, slaveName)
			}
			if err := syncZoneToProvider(ctx, zone, desired, exclude, types, slave, slaveName); err != nil {
				return fmt.Errorf("sync zone %q → %q: %w", zone, slaveName, err)
			}
		}
	}
	return nil
}

func syncZoneToProvider(
	ctx context.Context,
	zone string,
	desired []libdns.Record,
	exclude []string,
	types map[string]struct{},
	slave *providerRuntime,
	slaveName string,
) error {
	current, err := dnsRetryWithValue(slave.logLabel, "GetRecords(sync slave)", func() ([]libdns.Record, error) {
		return slave.client.GetRecords(ctx, zone)
	})
	if err != nil {
		return err
	}
	current = filterSyncRecords(current, zone, types, nil)

	desiredSet := make(map[syncRecKey]libdns.Record, len(desired))
	for _, r := range desired {
		desiredSet[syncRecordKey(r)] = r
	}

	var preserved []libdns.Record
	for _, r := range current {
		name := normalizeZoneRecordName(r.Name, zone)
		if recordNameExcluded(name, exclude) {
			preserved = append(preserved, r)
		}
	}

	var toApply []libdns.Record
	toApply = append(toApply, desired...)
	toApply = append(toApply, preserved...)

	setter, ok := slave.client.(interface {
		SetRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error)
	})
	if !ok {
		return fmt.Errorf("провайдер %q не поддерживает SetRecords", slaveName)
	}

	sort.Slice(toApply, func(i, j int) bool {
		ki, kj := syncRecordKey(toApply[i]), syncRecordKey(toApply[j])
		if ki.name != kj.name {
			return ki.name < kj.name
		}
		if ki.typ != kj.typ {
			return ki.typ < kj.typ
		}
		return ki.value < kj.value
	})

	slog.Info("sync: применение к slave", "zone", zone, "slave", slaveName, "records", len(toApply), "from_master", len(desired), "preserved_excluded", len(preserved))
	_, err = dnsRetryWithValue(slave.logLabel, "SetRecords(sync)", func() ([]libdns.Record, error) {
		return setter.SetRecords(ctx, zone, toApply)
	})
	return err
}

func validateSyncMasterAtLoad(z *SyncZoneConfig, registry map[string]*providerRuntime) error {
	if isFileMasterRef(z.Master) {
		path, err := parseFileMasterPath(z.Master)
		if err != nil {
			return err
		}
		st, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("файл master %q: %w", path, err)
		}
		if st.IsDir() {
			return fmt.Errorf("master %q — каталог, нужен .zone файл", path)
		}
		zone := normalizeZoneName(z.Zone)
		if _, err := loadRecordsFromZoneFile(path, zone); err != nil {
			return fmt.Errorf("разбор zone-файла %q: %w", path, err)
		}
		return nil
	}
	if _, ok := registry[z.Master]; !ok {
		return fmt.Errorf("неизвестный провайдер %q", z.Master)
	}
	return nil
}
