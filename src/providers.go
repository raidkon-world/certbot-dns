package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/libdns/alidns"
	"github.com/libdns/libdns"
	fastdns "github.com/nf404/libdns-fastdns"
)

const (
	providerTypeFastDNS      = "fastdns"
	providerTypeAlibabaCloud = "alibabacloud"
	defaultProviderName      = "default"
)

// dnsRecordsClient — минимальный libdns API для DNS-01 и проверки зоны.
type dnsRecordsClient interface {
	GetRecords(ctx context.Context, zone string) ([]libdns.Record, error)
	AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error)
	DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error)
}

type providerRuntime struct {
	name                string
	providerType        string
	client              dnsRecordsClient
	sequential          bool
	purgeConflictingTXT bool
	logLabel            string
}

func normalizeProviderType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case providerTypeFastDNS, "fast-dns":
		return providerTypeFastDNS
	case providerTypeAlibabaCloud, "alidns", "ali-dns", "alicloud":
		return providerTypeAlibabaCloud
	default:
		return strings.ToLower(strings.TrimSpace(t))
	}
}

func (c *Config) normalizeProviders() {
	if len(c.Providers) == 0 && strings.TrimSpace(c.FastDNS.APIToken) != "" {
		c.Providers = []ProviderConfig{{
			Name:     defaultProviderName,
			Type:     providerTypeFastDNS,
			APIToken: c.FastDNS.APIToken,
			APIURL:   c.FastDNS.APIURL,
		}}
	}
	for i := range c.Providers {
		c.Providers[i].Type = normalizeProviderType(c.Providers[i].Type)
		if strings.TrimSpace(c.Providers[i].Name) == "" {
			c.Providers[i].Name = fmt.Sprintf("provider-%d", i)
		}
	}
}

func (c *Config) buildProviderRegistry() (map[string]*providerRuntime, error) {
	c.normalizeProviders()
	if len(c.Providers) == 0 {
		return nil, fmt.Errorf("нужен хотя бы один [[providers]] или секция [fastdns] с api_token")
	}
	out := make(map[string]*providerRuntime, len(c.Providers))
	for i := range c.Providers {
		p := &c.Providers[i]
		name := strings.TrimSpace(p.Name)
		if name == "" {
			return nil, fmt.Errorf("providers[%d].name обязателен", i)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("дублирующееся имя providers: %q", name)
		}
		rt, err := buildProviderRuntime(p)
		if err != nil {
			return nil, fmt.Errorf("providers[%d] (%q): %w", i, name, err)
		}
		out[name] = rt
	}
	return out, nil
}

func buildProviderRuntime(p *ProviderConfig) (*providerRuntime, error) {
	switch p.Type {
	case providerTypeFastDNS:
		if strings.TrimSpace(p.APIToken) == "" {
			return nil, fmt.Errorf("type=fastdns: api_token пуст")
		}
		return &providerRuntime{
			name:         p.Name,
			providerType: providerTypeFastDNS,
			client: &fastdns.Provider{
				APIToken: p.APIToken,
				APIUrl:   p.APIURL,
			},
			sequential:          true,
			purgeConflictingTXT: true,
			logLabel:            "FastDNS",
		}, nil
	case providerTypeAlibabaCloud:
		if strings.TrimSpace(p.AccessKeyID) == "" {
			return nil, fmt.Errorf("type=alibabacloud: access_key_id пуст")
		}
		if strings.TrimSpace(p.AccessKeySecret) == "" {
			return nil, fmt.Errorf("type=alibabacloud: access_key_secret пуст")
		}
		if strings.TrimSpace(p.SecurityToken) != "" {
			return nil, fmt.Errorf("type=alibabacloud: security_token пока не поддерживается в libdns/alidns v1.0.4")
		}
		return &providerRuntime{
			name:         p.Name,
			providerType: providerTypeAlibabaCloud,
			client: &alidns.Provider{
				AccKeyID:     p.AccessKeyID,
				AccKeySecret: p.AccessKeySecret,
				RegionID:     p.RegionID,
			},
			logLabel: "Alibaba Cloud DNS",
		}, nil
	default:
		return nil, fmt.Errorf("неизвестный type %q (поддерживаются fastdns, alibabacloud)", p.Type)
	}
}

func verifyDNSZone(ctx context.Context, pr *providerRuntime, zone string) error {
	zone = strings.TrimSuffix(strings.TrimSpace(zone), ".")
	recs, err := dnsRetryWithValue(pr.logLabel, "GetRecords(verify zone)", func() ([]libdns.Record, error) {
		return pr.client.GetRecords(ctx, zone)
	})
	if err != nil {
		return fmt.Errorf("зона %q недоступна через %s (проверьте учётные данные и имя зоны): %w", zone, pr.logLabel, err)
	}
	_ = recs
	return nil
}
