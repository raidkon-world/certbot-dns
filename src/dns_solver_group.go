package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
)

type dnsSolverGroup struct {
	items []*dns01Solver
}

func newDNSSolverGroup(registry map[string]*providerRuntime, providers []string, zone string, propTimeout, propInterval time.Duration) (*dnsSolverGroup, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("список DNS-провайдеров пуст")
	}
	g := &dnsSolverGroup{items: make([]*dns01Solver, 0, len(providers))}
	for _, name := range providers {
		pr, ok := registry[name]
		if !ok {
			return nil, fmt.Errorf("неизвестный DNS-провайдер %q", name)
		}
		g.items = append(g.items, newDNS01Solver(pr, zone, propTimeout, propInterval))
	}
	return g, nil
}

func checkpointKeyForProvider(challengeKey, providerName string) string {
	return challengeKey + "|" + providerName
}

func (g *dnsSolverGroup) restoreTXTRecordIDs(from map[string]string) {
	if len(from) == 0 {
		return
	}
	for _, s := range g.items {
		subset := map[string]string{}
		suffix := "|" + s.providerName
		for k, id := range from {
			if strings.HasSuffix(k, suffix) {
				subset[strings.TrimSuffix(k, suffix)] = id
				continue
			}
			if len(g.items) == 1 && !strings.Contains(k, "|") {
				subset[k] = id
			}
		}
		s.restoreTXTRecordIDs(subset)
	}
}

func (g *dnsSolverGroup) attachCheckpointHooks(outputDir string) {
	for _, s := range g.items {
		attachCheckpointTXTHook(s, outputDir, s.providerName)
	}
}

func (g *dnsSolverGroup) Timeout() (timeout, interval time.Duration) {
	return g.items[0].Timeout()
}

func (g *dnsSolverGroup) Sequential() time.Duration {
	var wait time.Duration
	for _, s := range g.items {
		if d := s.Sequential(); d > wait {
			wait = d
		}
	}
	return wait
}

func (g *dnsSolverGroup) Present(domain, token, keyAuth string) error {
	for _, s := range g.items {
		if err := s.Present(domain, token, keyAuth); err != nil {
			return fmt.Errorf("provider %q: %w", s.providerName, err)
		}
	}
	return nil
}

func (g *dnsSolverGroup) CleanUp(domain, token, keyAuth string) error {
	var firstErr error
	for _, s := range g.items {
		if err := s.CleanUp(domain, token, keyAuth); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("provider %q: %w", s.providerName, err)
		}
	}
	return firstErr
}

var _ challenge.Provider = (*dnsSolverGroup)(nil)
var _ challenge.ProviderTimeout = (*dnsSolverGroup)(nil)
