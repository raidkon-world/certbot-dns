package main

import (
	"fmt"
	"strings"
)

// certProviderList — в TOML строка или массив строк ([[certificates]].provider).
type certProviderList []string

func (p *certProviderList) UnmarshalTOML(value any) error {
	switch v := value.(type) {
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			*p = nil
			return nil
		}
		*p = certProviderList{s}
		return nil
	case []any:
		out := make(certProviderList, 0, len(v))
		for i, item := range v {
			s, ok := item.(string)
			if !ok {
				return fmt.Errorf("provider[%d]: ожидается строка", i)
			}
			s = strings.TrimSpace(s)
			if s == "" {
				return fmt.Errorf("provider[%d]: пустое имя", i)
			}
			out = append(out, s)
		}
		*p = out
		return nil
	default:
		return fmt.Errorf("provider: нужна строка или массив строк")
	}
}

func (p certProviderList) names(defaultName string) []string {
	if len(p) == 0 {
		if defaultName == "" {
			defaultName = defaultProviderName
		}
		return []string{defaultName}
	}
	out := make([]string, 0, len(p))
	seen := make(map[string]struct{}, len(p))
	for _, name := range p {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	if len(out) == 0 {
		return []string{defaultProviderName}
	}
	return out
}

func (p certProviderList) label() string {
	return strings.Join(p.names(defaultProviderName), ",")
}
