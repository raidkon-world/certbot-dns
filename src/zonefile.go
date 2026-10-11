package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

const fileMasterPrefix = "file://"

func isFileMasterRef(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), fileMasterPrefix)
}

func parseFileMasterPath(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if !isFileMasterRef(ref) {
		return "", fmt.Errorf("не file:// master: %q", ref)
	}
	rest := strings.TrimPrefix(ref, fileMasterPrefix)
	if rest == "" {
		return "", fmt.Errorf("file:// без пути")
	}
	if strings.HasPrefix(rest, "/") {
		return filepath.Clean(rest), nil
	}
	return filepath.Clean("/" + rest), nil
}

// loadRecordsFromZoneFile читает BIND-подобный .zone (экспорт панели FastDNS и др.).
func loadRecordsFromZoneFile(path, expectedZone string) ([]libdns.Record, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	expectedZone = normalizeZoneName(expectedZone)
	var (
		defaultTTL time.Duration = time.Hour
		origin     string
		out        []libdns.Record
	)
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if i := strings.Index(line, ";"); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if line == "" {
				continue
			}
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "$TTL":
			if len(fields) < 2 {
				return nil, fmt.Errorf("%s:%d: $TTL без значения", path, lineNo)
			}
			d, err := parseZoneTTL(fields[1])
			if err != nil {
				return nil, fmt.Errorf("%s:%d: $TTL: %w", path, lineNo, err)
			}
			defaultTTL = d
			continue
		case "$ORIGIN":
			if len(fields) < 2 {
				return nil, fmt.Errorf("%s:%d: $ORIGIN без значения", path, lineNo)
			}
			origin = normalizeZoneName(strings.TrimSuffix(fields[1], "."))
			continue
		}
		if strings.HasPrefix(strings.ToUpper(line), "$") {
			continue
		}

		rec, err := parseZoneRecordLine(line, defaultTTL)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	zone := expectedZone
	if zone == "" && origin != "" {
		zone = origin
	}
	if zone != "" && origin != "" && origin != zone {
		return nil, fmt.Errorf("%s: $ORIGIN %q не совпадает с sync.zone %q", path, origin, zone)
	}
	for i := range out {
		out[i].Name = normalizeZoneRecordName(out[i].Name, zone)
	}
	return out, nil
}

func parseZoneTTL(s string) (time.Duration, error) {
	if n, err := strconv.Atoi(s); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(s)
}

func parseZoneRecordLine(line string, defaultTTL time.Duration) (libdns.Record, error) {
	line = strings.TrimSpace(line)
	tokens, err := tokenizeZoneLine(line)
	if err != nil {
		return libdns.Record{}, err
	}
	if len(tokens) < 3 {
		return libdns.Record{}, fmt.Errorf("мало полей в записи: %q", line)
	}
	idx := 0
	name := tokens[idx]
	idx++

	ttl := defaultTTL
	if idx < len(tokens) {
		if n, err := strconv.Atoi(tokens[idx]); err == nil && idx+1 < len(tokens) {
			ttl = time.Duration(n) * time.Second
			idx++
		}
	}
	if idx < len(tokens) && strings.EqualFold(tokens[idx], "IN") {
		idx++
	}
	if idx >= len(tokens) {
		return libdns.Record{}, fmt.Errorf("нет типа записи")
	}
	typ := strings.ToUpper(tokens[idx])
	idx++

	valuePart := ""
	if idx < len(tokens) {
		valuePart = strings.TrimSpace(strings.Join(tokens[idx:], " "))
	}

	rec := libdns.Record{
		Name: name,
		Type: typ,
		TTL:  ttl,
	}

	switch typ {
	case "MX":
		mxTokens, _ := tokenizeZoneLine(valuePart)
		if len(mxTokens) < 2 {
			return libdns.Record{}, fmt.Errorf("MX: нет priority/value")
		}
		prio, err := strconv.Atoi(mxTokens[0])
		if err != nil {
			return libdns.Record{}, fmt.Errorf("MX priority: %w", err)
		}
		rec.Priority = prio
		rec.Value = unquoteZoneField(strings.Join(mxTokens[1:], " "))
	case "TXT":
		rec.Value = parseZoneTXTValue(valuePart)
	default:
		rec.Value = unquoteZoneField(valuePart)
	}
	rec.Value = strings.TrimSuffix(rec.Value, ".")
	return rec, nil
}

// tokenizeZoneLine делит строку зоны на токены, не разбивая пробелы внутри "…".
func tokenizeZoneLine(line string) ([]string, error) {
	var tokens []string
	for i := 0; i < len(line); {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) {
			break
		}
		if line[i] == '"' {
			j := i + 1
			for j < len(line) {
				if line[j] == '\\' && j+1 < len(line) {
					j += 2
					continue
				}
				if line[j] == '"' {
					j++
					break
				}
				j++
			}
			tokens = append(tokens, line[i:j])
			i = j
			continue
		}
		j := i
		for j < len(line) && line[j] != ' ' && line[j] != '\t' {
			j++
		}
		tokens = append(tokens, line[i:j])
		i = j
	}
	return tokens, nil
}

func parseZoneTXTValue(valuePart string) string {
	tokens, err := tokenizeZoneLine(valuePart)
	if err != nil || len(tokens) == 0 {
		return unquoteZoneField(strings.TrimSpace(valuePart))
	}
	var parts []string
	for _, t := range tokens {
		parts = append(parts, unquoteZoneField(t))
	}
	return strings.Join(parts, "")
}

func unquoteZoneField(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return strings.ReplaceAll(s[1:len(s)-1], `\"`, `"`)
	}
	return s
}

func normalizeZoneName(z string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z)), ".")
}

func normalizeZoneRecordName(name, zone string) string {
	name = strings.TrimSpace(name)
	if name == "" || name == "@" {
		return "@"
	}
	name = strings.TrimSuffix(name, ".")
	zone = normalizeZoneName(zone)
	if zone != "" {
		suf := "." + zone
		if strings.HasSuffix(strings.ToLower(name), suf) {
			name = strings.TrimSuffix(name, suf)
			name = strings.TrimSuffix(name, ".")
		}
	}
	return name
}
