// Copyright 2015 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !nosystemd
// +build !nosystemd

package collector

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	systemdV2unitIncludeSet bool
	systemdV2unitInclude    = kingpin.Flag("collector.systemd-v2.unit-include", "Regexp of systemd units to include. Units must both match include and not match exclude to be included.").Default(".+").PreAction(func(c *kingpin.ParseContext) error {
		systemdV2unitIncludeSet = true
		return nil
	}).String()
	systemdV2unitExcludeSet bool
	systemdV2unitExclude    = kingpin.Flag("collector.systemd-v2.unit-exclude", "Regexp of systemd units to exclude. Units must both match include and not match exclude to be included.").Default(".+\\.(automount|device|mount|scope|slice|socket|timer|path|swap|target)").PreAction(func(c *kingpin.ParseContext) error {
		systemdV2unitExcludeSet = true
		return nil
	}).String()
)

const systemdV2subsystem = "systemd_v2"

type systemdV2Collector struct {
	unitStarts  *prometheus.Desc
	unitSuccess *prometheus.Desc
	unitFails   *prometheus.Desc
	// cli
	unitIncludePattern *regexp.Regexp
	unitExcludePattern *regexp.Regexp
	// system
	logger     log.Logger
	conn       *dbus.Conn
	unitStatus systemdV2Status
	ctx        context.Context
}

type systemdV2Status struct {
	mu          sync.RWMutex
	units       map[string]*systemdV2Unit
	lastUpdate  time.Time
	collectFail bool
}

type systemdV2Unit struct {
	status     string
	starts     uint
	fails      uint
	success    uint
	lastUpdate time.Time
}

func init() {
	registerCollector("systemd_v2", defaultDisabled, NewSystemdV2Collector)
}

// NewSystemdCollector returns a new Collector exposing systemd statistics.
func NewSystemdV2Collector(logger log.Logger) (Collector, error) {
	collector := &systemdV2Collector{
		logger: logger,
		ctx:    context.TODO(),
		unitStatus: systemdV2Status{
			units: make(map[string]*systemdV2Unit),
		},
	}

	collector.unitStarts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, systemdV2subsystem, "unit_starts"),
		"Count of unit starts", []string{"name"}, nil,
	)
	collector.unitSuccess = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, systemdV2subsystem, "unit_success"),
		"Count of unit starts", []string{"name"}, nil,
	)
	collector.unitFails = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, systemdV2subsystem, "unit_failed"),
		"Count of unit starts", []string{"name"}, nil,
	)

	level.Info(logger).Log("msg", "Parsed flag --collector.systemd-v2.unit-include", "flag", *systemdV2unitInclude)
	collector.unitIncludePattern = regexp.MustCompile(fmt.Sprintf("^(?:%s)$", *systemdV2unitInclude))
	level.Info(logger).Log("msg", "Parsed flag --collector.systemd-v2.unit-exclude", "flag", *systemdV2unitExclude)
	collector.unitExcludePattern = regexp.MustCompile(fmt.Sprintf("^(?:%s)$", *systemdV2unitExclude))

	var err error
	collector.conn, err = dbus.NewWithContext(collector.ctx)
	if err != nil {
		return nil, err
	}
	if err := collector.conn.Subscribe(); err != nil {
		return nil, err
	}

	dataCh := make(chan *dbus.PropertiesUpdate, 100)
	errCh := make(chan error)
	collector.conn.SetPropertiesSubscriber(dataCh, errCh)

	units, err := collector.conn.ListUnitsContext(collector.ctx)
	if err != nil {
		level.Error(logger).Log("msg", "collector failed", "name", systemdV2subsystem, "err", err)
		return nil, err
	}

	for _, unit := range units {
		if collector.unitMatchFilters(unit.Name) {
			if _, ok := collector.unitStatus.units[unit.Name]; !ok {
				collector.unitStatus.units[unit.Name] = &systemdV2Unit{}
			}
			collector.unitStatus.units[unit.Name].status = unit.ActiveState
		}
	}

	go collector.listener(dataCh, errCh)

	return collector, nil
}

// Update gathers metrics from systemd.  Dbus collection is done in parallel
// to reduce wait time for responses.
func (c *systemdV2Collector) Update(ch chan<- prometheus.Metric) error {
	c.unitStatus.mu.RLock()
	defer c.unitStatus.mu.RUnlock()

	if c.unitStatus.collectFail {
		return fmt.Errorf("systemd-v2 collector fail")
	}

	for unitName, unitStats := range c.unitStatus.units {
		ch <- prometheus.MustNewConstMetric(
			c.unitStarts,
			prometheus.CounterValue,
			float64(unitStats.starts),
			unitName,
		)
		ch <- prometheus.MustNewConstMetric(
			c.unitSuccess,
			prometheus.CounterValue,
			float64(unitStats.success),
			unitName,
		)
		ch <- prometheus.MustNewConstMetric(
			c.unitFails,
			prometheus.CounterValue,
			float64(unitStats.fails),
			unitName,
		)
	}

	return nil
}

func (c *systemdV2Collector) listener(dataChan <-chan *dbus.PropertiesUpdate, errChan <-chan error) {
	for {
		select {
		case data := <-dataChan:
			if !c.unitMatchFilters(data.UnitName) {
				continue
			}
			if _, ok := data.Changed["ActiveState"]; !ok {
				level.Warn(c.logger).Log("msg", "systemd-v2 unknown event", "unit", data.UnitName, "change", data.Changed)
				continue
			}

			c.unitStatus.mu.Lock()
			if _, ok := c.unitStatus.units[data.UnitName]; !ok {
				c.unitStatus.units[data.UnitName] = &systemdV2Unit{status: "activating", lastUpdate: time.Now(), starts: 1}
			} else if val := data.Changed["ActiveState"].Value().(string); c.unitStatus.units[data.UnitName].status != val {
				c.unitStatus.units[data.UnitName].status = val
				c.unitStatus.units[data.UnitName].lastUpdate = time.Now()
				switch val {
				case "activating":
					c.unitStatus.units[data.UnitName].starts += 1
				case "failed":
					c.unitStatus.units[data.UnitName].fails += 1
				case "deactivating":
				case "inactive":
					c.unitStatus.units[data.UnitName].success += 1
				default:
					level.Warn(c.logger).Log("msg", "Unknown unit state", "state", val, "change", data.Changed)
				}
			}
			c.unitStatus.lastUpdate = time.Now()
			c.unitStatus.mu.Unlock()
		case err := <-errChan:
			level.Error(c.logger).Log("msg", "collector failed", "name", systemdV2subsystem, "err", err)
			c.unitStatus.collectFail = true
		}
	}
}

func (c *systemdV2Collector) unitMatchFilters(name string) bool {
	if c.unitIncludePattern.MatchString(name) && !c.unitExcludePattern.MatchString(name) {
		return true
	}
	return false
}

func boolToFloat64(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
