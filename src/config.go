package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Config описывает TOML-конфиг (по умолчанию /etc/certbot-dns/config.toml).
type Config struct {
	ACME         ACMEConfig         `toml:"acme"`
	FastDNS      FastDNSConfig      `toml:"fastdns"`
	Providers    []ProviderConfig   `toml:"providers"`
	DNSChallenge DNSChallengeConfig `toml:"dns_challenge"`
	Certificates []CertConfig       `toml:"certificates"`
	Sync         SyncConfig         `toml:"sync"`
	Runtime      RuntimeConfig      `toml:"runtime"`
}

type ACMEConfig struct {
	Email     string `toml:"email"`
	Directory string `toml:"directory"` // production | staging
	StateDir  string `toml:"state_dir"`
	UserAgent string `toml:"user_agent"`
}

// FastDNSConfig — устаревший формат; при отсутствии [[providers]] создаётся провайдер name=default.
type FastDNSConfig struct {
	APIToken string `toml:"api_token"`
	APIURL   string `toml:"api_url"`
}

// ProviderConfig — один блок [[providers]].
type ProviderConfig struct {
	Name string `toml:"name"`
	Type string `toml:"type"`

	// fastdns
	APIToken string `toml:"api_token"`
	APIURL   string `toml:"api_url"`

	// alibabacloud (Alibaba Cloud DNS / AliDNS)
	AccessKeyID     string `toml:"access_key_id"`
	AccessKeySecret string `toml:"access_key_secret"`
	RegionID        string `toml:"region_id"`
	SecurityToken   string `toml:"security_token"`
}

type DNSChallengeConfig struct {
	PropagationTimeout  string   `toml:"propagation_timeout"`
	PropagationInterval string   `toml:"propagation_interval"`
	RecursiveResolvers  []string `toml:"recursive_resolvers"`
}

type CertConfig struct {
	ID              string           `toml:"id"`
	ProviderRaw     any              `toml:"provider"`
	Providers       certProviderList `toml:"-"`
	Domains         []string         `toml:"domains"`
	OutputDir       string   `toml:"output_dir"`
	KeyType         string   `toml:"key_type"`
	RenewBeforeDays int      `toml:"renew_before_days"`
}

type SyncConfig struct {
	Enabled      bool             `toml:"enabled"`
	Interval     string           `toml:"interval"`
	RecordTypes  []string         `toml:"record_types"`
	ExcludeNames []string         `toml:"exclude_names"`
	Zones        []SyncZoneConfig `toml:"zones"`
}

type SyncZoneConfig struct {
	Zone   string   `toml:"zone"`
	Master string   `toml:"master"`
	Slaves []string `toml:"slaves"`
}

type RuntimeConfig struct {
	Mode       string `toml:"mode"` // once | daemon
	PollWhenOK string `toml:"poll_when_ok"`
	Loglevel   string `toml:"loglevel"`
}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := toml.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	c.applyDefaults()
	expandEnvInConfig(&c)
	if err := c.finalizeCertProviders(); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.ACME.Directory == "" {
		c.ACME.Directory = "production"
	}
	if c.ACME.StateDir == "" {
		c.ACME.StateDir = ".acme-state"
	}
	if c.ACME.UserAgent == "" {
		c.ACME.UserAgent = "certbot-dns/1"
	}
	if c.DNSChallenge.PropagationTimeout == "" {
		c.DNSChallenge.PropagationTimeout = "24h"
	}
	if c.DNSChallenge.PropagationInterval == "" {
		c.DNSChallenge.PropagationInterval = "10m"
	}
	if c.Sync.Interval == "" {
		c.Sync.Interval = syncIntervalOnStart
	}
	if c.Runtime.Mode == "" {
		c.Runtime.Mode = "once"
	}
	if c.Runtime.PollWhenOK == "" {
		c.Runtime.PollWhenOK = "24h"
	}
	if c.Runtime.Loglevel == "" {
		c.Runtime.Loglevel = "info"
	}
	for i := range c.Certificates {
		e := &c.Certificates[i]
		if e.RenewBeforeDays <= 0 {
			e.RenewBeforeDays = 25
		}
		if e.KeyType == "" {
			e.KeyType = "ec256"
		}
	}
	c.normalizeProviders()
}

func (c *Config) finalizeCertProviders() error {
	for i := range c.Certificates {
		e := &c.Certificates[i]
		if len(e.Providers) == 0 {
			if e.ProviderRaw == nil {
				e.Providers = certProviderList{defaultProviderName}
				continue
			}
			var pl certProviderList
			if err := pl.UnmarshalTOML(e.ProviderRaw); err != nil {
				return fmt.Errorf("certificates[%d].provider: %w", i, err)
			}
			e.Providers = pl
		}
	}
	return nil
}

func expandEnvInConfig(c *Config) {
	c.ACME.Email = os.ExpandEnv(c.ACME.Email)
	c.ACME.StateDir = os.ExpandEnv(c.ACME.StateDir)
	c.ACME.UserAgent = os.ExpandEnv(c.ACME.UserAgent)
	c.FastDNS.APIToken = os.ExpandEnv(c.FastDNS.APIToken)
	c.FastDNS.APIURL = os.ExpandEnv(c.FastDNS.APIURL)
	c.Runtime.Loglevel = os.ExpandEnv(c.Runtime.Loglevel)
	for i := range c.Providers {
		p := &c.Providers[i]
		p.Name = os.ExpandEnv(p.Name)
		p.APIToken = os.ExpandEnv(p.APIToken)
		p.APIURL = os.ExpandEnv(p.APIURL)
		p.AccessKeyID = os.ExpandEnv(p.AccessKeyID)
		p.AccessKeySecret = os.ExpandEnv(p.AccessKeySecret)
		p.RegionID = os.ExpandEnv(p.RegionID)
		p.SecurityToken = os.ExpandEnv(p.SecurityToken)
	}
	for i := range c.DNSChallenge.RecursiveResolvers {
		c.DNSChallenge.RecursiveResolvers[i] = os.ExpandEnv(c.DNSChallenge.RecursiveResolvers[i])
	}
	for i := range c.Certificates {
		e := &c.Certificates[i]
		e.ID = os.ExpandEnv(e.ID)
		for j := range e.Providers {
			e.Providers[j] = os.ExpandEnv(e.Providers[j])
		}
		e.OutputDir = os.ExpandEnv(e.OutputDir)
		for j := range e.Domains {
			e.Domains[j] = os.ExpandEnv(e.Domains[j])
		}
	}
	for i := range c.Sync.Zones {
		z := &c.Sync.Zones[i]
		z.Zone = os.ExpandEnv(z.Zone)
		z.Master = os.ExpandEnv(z.Master)
		if isFileMasterRef(z.Master) {
			if p, err := parseFileMasterPath(z.Master); err == nil {
				z.Master = fileMasterPrefix + p
			}
		}
		for j := range z.Slaves {
			z.Slaves[j] = os.ExpandEnv(z.Slaves[j])
		}
	}
}

func (c *Config) validate() error {
	if strings.TrimSpace(c.ACME.Email) == "" {
		return fmt.Errorf("acme.email обязателен")
	}
	dir := strings.ToLower(strings.TrimSpace(c.ACME.Directory))
	switch dir {
	case "production", "staging":
	default:
		return fmt.Errorf("acme.directory должен быть production или staging, сейчас %q", c.ACME.Directory)
	}
	registry, err := c.buildProviderRegistry()
	if err != nil {
		return err
	}
	if _, err := time.ParseDuration(c.DNSChallenge.PropagationTimeout); err != nil {
		return fmt.Errorf("dns_challenge.propagation_timeout: %w", err)
	}
	if _, err := time.ParseDuration(c.DNSChallenge.PropagationInterval); err != nil {
		return fmt.Errorf("dns_challenge.propagation_interval: %w", err)
	}
	if c.Sync.Enabled {
		if _, _, err := parseSyncInterval(c.Sync.Interval); err != nil {
			return fmt.Errorf("sync.interval: %w", err)
		}
		if len(c.Sync.Zones) == 0 {
			return fmt.Errorf("sync.enabled=true: нужен хотя бы один [[sync.zones]]")
		}
		for i := range c.Sync.Zones {
			z := &c.Sync.Zones[i]
			if strings.TrimSpace(z.Zone) == "" {
				return fmt.Errorf("sync.zones[%d].zone обязателен", i)
			}
			if strings.TrimSpace(z.Master) == "" {
				return fmt.Errorf("sync.zones[%d].master обязателен", i)
			}
			if err := validateSyncMasterAtLoad(z, registry); err != nil {
				return fmt.Errorf("sync.zones[%d].master: %w", i, err)
			}
			if len(z.Slaves) == 0 {
				return fmt.Errorf("sync.zones[%d].slaves не может быть пустым", i)
			}
			for j, s := range z.Slaves {
				if _, ok := registry[s]; !ok {
					return fmt.Errorf("sync.zones[%d].slaves[%d]: неизвестный провайдер %q", i, j, s)
				}
			}
		}
	}
	mode := strings.ToLower(strings.TrimSpace(c.Runtime.Mode))
	switch mode {
	case "once", "daemon":
	default:
		return fmt.Errorf("runtime.mode должен быть once или daemon, сейчас %q", c.Runtime.Mode)
	}
	if _, err := time.ParseDuration(c.Runtime.PollWhenOK); err != nil {
		return fmt.Errorf("runtime.poll_when_ok: %w", err)
	}
	if _, err := parseLoggingSetup(c.Runtime.Loglevel); err != nil {
		return err
	}
	if len(c.Certificates) == 0 {
		return fmt.Errorf("нужен хотя бы один блок [[certificates]]")
	}
	for i := range c.Certificates {
		e := &c.Certificates[i]
		if len(e.Domains) == 0 {
			return fmt.Errorf("certificates[%d].domains не может быть пустым", i)
		}
		if strings.TrimSpace(e.OutputDir) == "" {
			return fmt.Errorf("certificates[%d].output_dir обязателен", i)
		}
		for j, pname := range e.Providers.names(defaultProviderName) {
			if _, ok := registry[pname]; !ok {
				return fmt.Errorf("certificates[%d].provider[%d]: неизвестный провайдер %q", i, j, pname)
			}
		}
		if _, err := parseKeyType(e.KeyType); err != nil {
			return fmt.Errorf("certificates[%d].key_type: %w", i, err)
		}
		if _, err := expandCertEntry(*e, i, registry); err != nil {
			return fmt.Errorf("certificates[%d] domains: %w", i, err)
		}
	}
	return nil
}

func (c *Config) propagationDurations() (timeout, interval time.Duration, err error) {
	timeout, err = time.ParseDuration(c.DNSChallenge.PropagationTimeout)
	if err != nil {
		return 0, 0, err
	}
	interval, err = time.ParseDuration(c.DNSChallenge.PropagationInterval)
	if err != nil {
		return 0, 0, err
	}
	return timeout, interval, nil
}

func (c *Config) pollWhenOKDuration() (time.Duration, error) {
	return time.ParseDuration(c.Runtime.PollWhenOK)
}

func (c *Config) runtimeMode() string {
	return strings.ToLower(strings.TrimSpace(c.Runtime.Mode))
}

func certLabel(c CertConfig, idx int) string {
	if strings.TrimSpace(c.ID) != "" {
		return c.ID
	}
	return fmt.Sprintf("#%d", idx)
}
