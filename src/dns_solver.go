package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/libdns/libdns"
)

type dns01Solver struct {
	zone   string
	client dnsRecordsClient

	providerName          string
	logLabel              string
	sequential            bool
	purgeTXTBeforePresent bool

	propagationTimeout  time.Duration
	propagationInterval time.Duration

	afterTXTCreate func(challengeKey, recordID string)

	mu  sync.Mutex
	ids map[string]string
}

func newDNS01Solver(pr *providerRuntime, zone string, propTimeout, propInterval time.Duration) *dns01Solver {
	return &dns01Solver{
		zone:                  strings.TrimSuffix(strings.TrimSpace(zone), "."),
		client:                pr.client,
		providerName:          pr.name,
		logLabel:              pr.logLabel,
		sequential:            pr.sequential,
		purgeTXTBeforePresent: pr.purgeConflictingTXT,
		propagationTimeout:    propTimeout,
		propagationInterval:   propInterval,
	}
}

func (s *dns01Solver) Timeout() (timeout, interval time.Duration) {
	return s.propagationTimeout, s.propagationInterval
}

func (s *dns01Solver) Sequential() time.Duration {
	if !s.sequential {
		return 0
	}
	if s.propagationInterval > 0 {
		return s.propagationInterval
	}
	return 5 * time.Second
}

func (s *dns01Solver) challengeKey(domain, keyAuth string) string {
	return normalizeFQDN(dns01.GetChallengeInfo(domain, keyAuth).EffectiveFQDN)
}

func (s *dns01Solver) restoreTXTRecordIDs(from map[string]string) {
	if len(from) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ids == nil {
		s.ids = make(map[string]string)
	}
	for k, id := range from {
		if k != "" && id != "" {
			s.ids[k] = id
		}
	}
}

func (s *dns01Solver) normalizeTXTRecordName(recName string) string {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(recName)), ".")
	z := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s.zone), "."))
	if z != "" && strings.HasSuffix(n, "."+z) {
		n = strings.TrimSuffix(n, "."+z)
	}
	return n
}

func dnsHTTPRetriable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "eof") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "tls: bad record mac") ||
		strings.Contains(msg, "502 bad gateway") ||
		strings.Contains(msg, "503 service") ||
		strings.Contains(msg, "504 gateway") ||
		strings.Contains(msg, "429 too many")
}

func dnsRetryWithValue[T any](logLabel, op string, fn func() (T, error)) (T, error) {
	var zero T
	delays := []time.Duration{0, 400 * time.Millisecond, 1 * time.Second, 2 * time.Second, 4 * time.Second}
	var lastErr error
	for attempt := range delays {
		if delays[attempt] > 0 {
			time.Sleep(delays[attempt])
		}
		v, err := fn()
		if err == nil {
			if attempt > 0 {
				slog.Info("DNS API: успех после повтора", "provider", logLabel, "op", op, "attempt", attempt+1)
			}
			return v, nil
		}
		lastErr = err
		if !dnsHTTPRetriable(err) || attempt == len(delays)-1 {
			return zero, err
		}
		slog.Warn("DNS API: временная ошибка, повтор", "provider", logLabel, "op", op, "attempt", attempt+1, "err", err)
	}
	return zero, lastErr
}

func (s *dns01Solver) purgeConflictingTXT(ctx context.Context, relName string) (removed int, err error) {
	recs, err := dnsRetryWithValue(s.logLabel, "GetRecords(purge)", func() ([]libdns.Record, error) {
		return s.client.GetRecords(ctx, s.zone)
	})
	if err != nil {
		return 0, err
	}
	target := s.normalizeTXTRecordName(relName)
	var deletedIDs []string
	for _, r := range recs {
		if !strings.EqualFold(strings.TrimSpace(r.Type), "TXT") {
			continue
		}
		if strings.TrimSpace(r.ID) == "" {
			continue
		}
		if s.normalizeTXTRecordName(r.Name) != target {
			continue
		}
		_, delErr := dnsRetryWithValue(s.logLabel, fmt.Sprintf("DeleteRecords(purge) id=%s", r.ID), func() (struct{}, error) {
			_, e := s.client.DeleteRecords(ctx, s.zone, []libdns.Record{{ID: r.ID}})
			return struct{}{}, e
		})
		if delErr != nil {
			return removed, fmt.Errorf("DeleteRecords TXT id=%s name=%q: %w", r.ID, r.Name, delErr)
		}
		deletedIDs = append(deletedIDs, r.ID)
		removed++
		slog.Debug("purge: удалена TXT перед ACME Present", "provider", s.providerName, "zone", s.zone, "record_id", r.ID, "name", r.Name)
	}
	if len(deletedIDs) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	for chKey, id := range s.ids {
		for _, did := range deletedIDs {
			if id == did {
				delete(s.ids, chKey)
				break
			}
		}
	}
	s.mu.Unlock()
	slog.Info("очищены старые TXT для DNS-01", "provider", s.providerName, "zone", s.zone, "relative_name", relName, "removed", removed)
	return removed, nil
}

func (s *dns01Solver) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	name := recordNameForZone(info.EffectiveFQDN, s.zone)
	ctx := context.Background()

	if s.purgeTXTBeforePresent {
		if _, err := s.purgeConflictingTXT(ctx, name); err != nil {
			return fmt.Errorf("очистка TXT перед Present: %w", err)
		}
	}

	k := s.challengeKey(domain, keyAuth)
	s.mu.Lock()
	already := s.ids[k] != ""
	s.mu.Unlock()
	if already {
		slog.Debug("DNS-01 Present: пропуск (запись уже в памяти/чекпоинте)", "challenge_key", k, "acme_identifier", domain)
		return nil
	}

	slog.Debug("DNS-01 Present",
		"provider", s.providerName,
		"acme_identifier", domain,
		"txt_fqdn", info.EffectiveFQDN,
		"txt_name_in_zone", name,
		"dns_zone", s.zone,
		"ttl_sec", dns01.DefaultTTL,
	)

	rec := libdns.Record{
		Type:  "TXT",
		Name:  name,
		Value: info.Value,
		TTL:   time.Duration(dns01.DefaultTTL) * time.Second,
	}

	added, err := dnsRetryWithValue(s.logLabel, "AppendRecords", func() ([]libdns.Record, error) {
		return s.client.AppendRecords(ctx, s.zone, []libdns.Record{rec})
	})
	if err != nil {
		if strings.TrimSpace(err.Error()) == "" {
			slog.Warn("AppendRecords: пустое message в ошибке API",
				"provider", s.providerName, "txt_name_in_zone", name, "dns_zone", s.zone)
			return fmt.Errorf("%s AppendRecords (name=%q zone=%q): пустой ответ API", s.logLabel, name, s.zone)
		}
		return fmt.Errorf("%s AppendRecords (name=%q zone=%q): %w", s.logLabel, name, s.zone, err)
	}
	if len(added) == 0 || added[0].ID == "" {
		return fmt.Errorf("%s: пустой ответ AppendRecords (нет ID записи)", s.logLabel)
	}

	recID := added[0].ID
	s.mu.Lock()
	if s.ids == nil {
		s.ids = make(map[string]string)
	}
	s.ids[k] = recID
	cb := s.afterTXTCreate
	s.mu.Unlock()

	if cb != nil {
		cb(k, recID)
	}

	slog.Info("DNS TXT создан", "provider", s.providerName, "zone", s.zone, "record_id", recID, "name", name, "acme_identifier", domain)
	return nil
}

func (s *dns01Solver) CleanUp(domain, token, keyAuth string) error {
	k := s.challengeKey(domain, keyAuth)
	s.mu.Lock()
	id := s.ids[k]
	delete(s.ids, k)
	s.mu.Unlock()
	if id == "" {
		slog.Debug("DNS-01 CleanUp: запись уже удалена или не отслеживалась", "acme_identifier", domain)
		return nil
	}

	ctx := context.Background()
	slog.Debug("DNS-01 CleanUp", "provider", s.providerName, "zone", s.zone, "record_id", id, "acme_identifier", domain)
	_, err := dnsRetryWithValue(s.logLabel, "DeleteRecords(cleanup)", func() (struct{}, error) {
		_, e := s.client.DeleteRecords(ctx, s.zone, []libdns.Record{{ID: id}})
		return struct{}{}, e
	})
	if err != nil {
		return fmt.Errorf("%s DeleteRecords: %w", s.logLabel, err)
	}
	slog.Info("DNS TXT удалён", "provider", s.providerName, "zone", s.zone, "record_id", id)
	return nil
}

var _ challenge.Provider = (*dns01Solver)(nil)
var _ challenge.ProviderTimeout = (*dns01Solver)(nil)
