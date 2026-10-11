package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "/etc/certbot-dns/config.toml", "путь к TOML-конфигу")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "конфиг %s: %v\n", *configPath, err)
		os.Exit(2)
	}

	if err := initAppLogging(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "логирование: %v\n", err)
		os.Exit(2)
	}

	registry, err := cfg.buildProviderRegistry()
	if err != nil {
		fmt.Fprintf(os.Stderr, "провайдеры DNS: %v\n", err)
		os.Exit(2)
	}

	expanded, err := expandAllCerts(cfg.Certificates, registry)
	if err != nil {
		slog.Error("разбор domains", "err", err)
		os.Exit(2)
	}
	slog.Info("конфиг применён", "config_path", *configPath, "version", version, "dns_providers", len(registry), "expanded_certs", len(expanded), "raw_certificates_blocks", len(cfg.Certificates))
	for i := range expanded {
		e := &expanded[i]
		slog.Debug("выпуск из конфига", "index", i, "label", e.Label, "providers", e.Providers, "zone", e.Zone, "san", e.Domains, "output_dir", e.OutputDir, "renew_before_days", e.RenewBeforeDays, "key_type", e.KeyType)
	}

	propTimeout, propInterval, err := cfg.propagationDurations()
	if err != nil {
		slog.Error("длительности DNS", "err", err)
		os.Exit(2)
	}
	slog.Debug("dns_challenge тайминги", "propagation_timeout", propTimeout, "propagation_interval", propInterval)

	dnsOpts, err := buildDNSOpts(cfg)
	if err != nil {
		slog.Error("dns opts", "err", err)
		os.Exit(2)
	}
	slog.Debug("рекурсивные резолверы для проверки DNS (TXT propagation)", "resolvers", effectivePropagationResolvers(cfg))

	ctx := context.Background()
	type zoneKey struct {
		provider string
		zone     string
	}
	zoneLabels := map[zoneKey][]string{}
	for i := range expanded {
		z := strings.TrimSuffix(strings.TrimSpace(expanded[i].Zone), ".")
		for _, pname := range expanded[i].Providers {
			k := zoneKey{provider: pname, zone: z}
			zoneLabels[k] = append(zoneLabels[k], expanded[i].Label)
		}
	}
	keys := make([]zoneKey, 0, len(zoneLabels))
	for k := range zoneLabels {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].provider != keys[j].provider {
			return keys[i].provider < keys[j].provider
		}
		return keys[i].zone < keys[j].zone
	})
	for _, k := range keys {
		labels := zoneLabels[k]
		pr := registry[k.provider]
		slog.Debug("проверка зоны DNS", "provider", k.provider, "zone", k.zone, "cert_labels", labels)
		if err := verifyDNSZone(ctx, pr, k.zone); err != nil {
			slog.Error("зона недоступна", "provider", k.provider, "zone", k.zone, "cert_labels", labels, "err", err)
			os.Exit(1)
		}
		slog.Info("зона DNS доступна", "provider", k.provider, "zone", k.zone, "cert_labels", labels)
	}

	for cycle := 0; ; cycle++ {
		now := time.Now()
		slog.Debug("цикл проверки/выпуска", "cycle", cycle, "time_utc", now.UTC().Format(time.RFC3339Nano))
		if err := runRenewals(cfg, registry, expanded, now, propTimeout, propInterval, dnsOpts); err != nil {
			slog.Error("ошибка цикла", "err", err)
			os.Exit(1)
		}

		if cfg.syncRunsEveryCycle(cycle) {
			if err := runDNSSync(ctx, cfg, registry); err != nil {
				slog.Error("sync DNS", "err", err)
				os.Exit(1)
			}
		}

		if cfg.runtimeMode() == "once" {
			slog.Info("режим once: завершение без ошибок")
			return
		}

		d, err := sleepUntilNextCheck(expanded, cfg, time.Now())
		if err != nil {
			slog.Error("расчёт паузы", "err", err)
			os.Exit(1)
		}
		if cap, ok := cfg.syncSleepCap(); ok && (d <= 0 || cap < d) {
			d = cap
		}
		if d <= 0 {
			d = time.Minute
		}
		slog.Info("ожидание до следующей проверки", "sleep", d.Round(time.Second), "mode", cfg.runtimeMode())
		time.Sleep(d)
	}
}

func nonEmptyOrDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func runRenewals(
	cfg *Config,
	registry map[string]*providerRuntime,
	expanded []ExpandedCert,
	now time.Time,
	propTimeout, propInterval time.Duration,
	dnsOpts []dns01.ChallengeOption,
) error {
	for i := range expanded {
		e := &expanded[i]
		path := resolveFullchainReadPath(e.OutputDir)

		need, exp, err := needsRenewal(e, now)
		if err != nil {
			slog.Warn("не удалось прочитать существующий сертификат", "label", e.Label, "path", path, "err", err)
			return fmt.Errorf("%s: %w", e.Label, err)
		}
		if !need {
			slog.Info("сертификат актуален",
				"label", e.Label,
				"path", path,
				"not_after_utc", exp.UTC().Format(time.RFC3339),
				"days_until_expiry", int(time.Until(exp).Hours()/24),
				"renew_before_days", e.RenewBeforeDays,
			)
			slog.Debug("пропуск выпуска", "label", e.Label, "fullchain", path)
			continue
		}

		slog.Info("запуск ACME Obtain", "label", e.Label, "providers", e.Providers, "san", e.Domains, "dns_zone", e.Zone, "key_type", e.KeyType, "out_dir", e.OutputDir)
		if err := obtainCertificate(cfg, registry, propTimeout, propInterval, dnsOpts, *e); err != nil {
			slog.Error("Obtain не удался", "label", e.Label, "err", err)
			return fmt.Errorf("%s: %w", e.Label, err)
		}
		slog.Info("сертификаты записаны на диск", "label", e.Label, "fullchain", resolveFullchainReadPath(e.OutputDir), "privkey", resolvePrivkeyReadPath(e.OutputDir))
	}
	return nil
}

func needsRenewal(e *ExpandedCert, now time.Time) (need bool, notAfter time.Time, err error) {
	path := resolveFullchainReadPath(e.OutputDir)
	exp, err := leafNotAfter(path)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Debug("fullchain отсутствует — требуется выпуск", "path", path, "label", e.Label)
			return true, time.Time{}, nil
		}
		return false, time.Time{}, err
	}
	deadline := exp.Add(-time.Duration(e.RenewBeforeDays) * 24 * time.Hour)
	if !now.Before(deadline) {
		slog.Debug("срок продления наступил", "label", e.Label, "not_after", exp.UTC().Format(time.RFC3339), "deadline_renew_utc", deadline.UTC().Format(time.RFC3339), "renew_before_days", e.RenewBeforeDays)
		return true, exp, nil
	}
	slog.Debug("срок продления не наступил", "label", e.Label, "deadline_renew_utc", deadline.UTC().Format(time.RFC3339))
	return false, exp, nil
}

func leafNotAfter(fullchainPath string) (time.Time, error) {
	data, err := os.ReadFile(fullchainPath)
	if err != nil {
		return time.Time{}, err
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return time.Time{}, fmt.Errorf("в %s нет блока CERTIFICATE", fullchainPath)
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, err
		}
		return cert.NotAfter, nil
	}
}

func sleepUntilNextCheck(expanded []ExpandedCert, cfg *Config, now time.Time) (time.Duration, error) {
	pollOK, err := cfg.pollWhenOKDuration()
	if err != nil {
		return 0, err
	}

	var minRemain time.Duration = -1
	var minLabel string
	for i := range expanded {
		e := &expanded[i]
		path := resolveFullchainReadPath(e.OutputDir)
		exp, err := leafNotAfter(path)
		if err != nil {
			slog.Debug("sleepUntilNextCheck: нет/битый fullchain — короткая пауза", "label", e.Label, "path", path, "err", err)
			return time.Minute, nil
		}
		renewBy := exp.Add(-time.Duration(e.RenewBeforeDays) * 24 * time.Hour)
		remain := renewBy.Sub(now)
		slog.Debug("расчёт сна до продления", "label", e.Label, "not_after_utc", exp.UTC().Format(time.RFC3339), "renew_by_utc", renewBy.UTC().Format(time.RFC3339), "remain", remain.Round(time.Second))
		if remain <= 0 {
			return time.Minute, nil
		}
		if minRemain < 0 || remain < minRemain {
			minRemain = remain
			minLabel = e.Label
		}
	}

	if minRemain < 0 {
		slog.Debug("ограничение сна poll_when_ok (нет валидных сроков)", "poll_when_ok", pollOK)
		return pollOK, nil
	}
	if minRemain > pollOK {
		slog.Debug("сон ограничен poll_when_ok", "would_sleep", minRemain.Round(time.Second), "capped_to", pollOK, "next_renew_label", minLabel)
		return pollOK, nil
	}
	if minRemain < time.Minute {
		return time.Minute, nil
	}
	slog.Debug("сон до ближайшего продления", "sleep", minRemain.Round(time.Second), "label", minLabel)
	return minRemain, nil
}
