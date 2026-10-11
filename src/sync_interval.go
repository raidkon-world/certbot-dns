package main

import (
	"fmt"
	"strings"
	"time"
)

const syncIntervalOnStart = "onstart"

func parseSyncInterval(s string) (onStartOnly bool, every time.Duration, err error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == syncIntervalOnStart {
		return true, 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return false, 0, fmt.Errorf("ожидается %q или длительность Go (например 5m), сейчас %q", syncIntervalOnStart, s)
	}
	if d <= 0 {
		return false, 0, fmt.Errorf("длительность должна быть > 0")
	}
	return false, d, nil
}

func (c *Config) syncRunsEveryCycle(cycle int) bool {
	if !c.Sync.Enabled {
		return false
	}
	onStart, _, err := parseSyncInterval(c.Sync.Interval)
	if err != nil {
		return false
	}
	if onStart {
		return cycle == 0
	}
	return true
}

func (c *Config) syncSleepCap() (time.Duration, bool) {
	onStart, every, err := parseSyncInterval(c.Sync.Interval)
	if err != nil || onStart {
		return 0, false
	}
	return every, true
}
