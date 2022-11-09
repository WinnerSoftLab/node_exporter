package collector

import (
	"fmt"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tidwall/gjson"
	"gopkg.in/alecthomas/kingpin.v2"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	smartctlPath = kingpin.Flag("collector.smartctl.path",
		"The path to the smartctl binary",
	).Default("/usr/sbin/smartctl").String()
	smartctlInterval = kingpin.Flag("collector.smartctl.interval",
		"The interval between smarctl polls",
	).Default("300s").Duration()
	smartctlDevices = kingpin.Flag("collector.smartctl.device",
		"The device to monitor (repeatable)",
	).Strings()
)

type SMARTDevice struct {
	device string
	serial string
	family string
	model  string
}

type SMARTctl struct {
	ch     chan<- prometheus.Metric
	json   gjson.Result
	logger log.Logger
	device SMARTDevice
}

// SMARTctlInfo object
type SMARTctlInfo struct {
	ch    chan<- prometheus.Metric
	json  gjson.Result
	Ready bool
}

type diskDevice struct {
	name       string
	deviceType string
}

type smartCollector struct {
	smartctlVersion, smartctlDevice               *prometheus.Desc
	capacityBlocks, capacityBytes                 *prometheus.Desc
	blockSize, interfaceSpeed                     *prometheus.Desc
	attribute, powerOnSeconds                     *prometheus.Desc
	rotationRate, temperature                     *prometheus.Desc
	powerCycleCount, percentageUsed               *prometheus.Desc
	availableSpare, availableSpareThreshold       *prometheus.Desc
	criticalWarning, mediaErrors                  *prometheus.Desc
	numErrLogEntries, bytesRead                   *prometheus.Desc
	bytesWritten, smartStatus, smartctlExitStatus *prometheus.Desc
	state, statistics, status, errorLogCount      *prometheus.Desc
	selfTestLogCount, selfTestLogErrorCount       *prometheus.Desc
	ercSeconds                                    *prometheus.Desc
	logger                                        log.Logger
	devices                                       []diskDevice
}

// JSONCache caching json
type JSONCache struct {
	JSON        gjson.Result
	LastCollect time.Time
}

var (
	jsonCache sync.Map
)

var (
	metricSmartctlVersion = prometheus.NewDesc(
		"smartctl_version",
		"smartctl version",
		[]string{
			"json_format_version",
			"smartctl_version",
			"svn_revision",
			"build_info",
		},
		nil,
	)
	metricDeviceModel = prometheus.NewDesc(
		"smartctl_device",
		"Device info",
		[]string{
			"device",
			"interface",
			"protocol",
			"model_family",
			"model_name",
			"serial_number",
			"ata_additional_product_id",
			"firmware_version",
			"ata_version",
			"sata_version",
			"form_factor",
		},
		nil,
	)

	metricDeviceAttribute = prometheus.NewDesc(
		"smartctl_device_attribute",
		"Device attributes",
		[]string{
			"device",
			"attribute_name",
			"attribute_flags_short",
			"attribute_flags_long",
			"attribute_value_type",
			"attribute_id",
		},
		nil,
	)
	metricDeviceTemperature = prometheus.NewDesc(
		"smartctl_device_temperature",
		"Device temperature celsius",
		[]string{
			"device",
			"temperature_type",
		},
		nil,
	)
	metricDevicePercentageUsed = prometheus.NewDesc(
		"smartctl_device_percentage_used",
		"Device write percentage used",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceAvailableSpare = prometheus.NewDesc(
		"smartctl_device_available_spare",
		"Normalized percentage (0 to 100%) of the remaining spare capacity available",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceAvailableSpareThreshold = prometheus.NewDesc(
		"smartctl_device_available_spare_threshold",
		"When the Available Spare falls below the threshold indicated in this field, an asynchronous event completion may occur. The value is indicated as a normalized percentage (0 to 100%)",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceCriticalWarning = prometheus.NewDesc(
		"smartctl_device_critical_warning",
		"This field indicates critical warnings for the state of the controller",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceMediaErrors = prometheus.NewDesc(
		"smartctl_device_media_errors",
		"Contains the number of occurrences where the controller detected an unrecovered data integrity error. Errors such as uncorrectable ECC, CRC checksum failure, or LBA tag mismatch are included in this field",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceNumErrLogEntries = prometheus.NewDesc(
		"smartctl_device_num_err_log_entries",
		"Contains the number of Error Information log entries over the life of the controller",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceBytesRead = prometheus.NewDesc(
		"smartctl_device_bytes_read",
		"",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceBytesWritten = prometheus.NewDesc(
		"smartctl_device_bytes_written",
		"",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceSmartStatus = prometheus.NewDesc(
		"smartctl_device_smart_status",
		"General smart status",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceExitStatus = prometheus.NewDesc(
		"smartctl_device_smartctl_exit_status",
		"Exit status of smartctl on device",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceState = prometheus.NewDesc(
		"smartctl_device_state",
		"Device state (0=active, 1=standby, 2=sleep, 3=dst, 4=offline, 5=sct)",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceStatistics = prometheus.NewDesc(
		"smartctl_device_statistics",
		"Device statistics",
		[]string{
			"device",
			"statistic_table",
			"statistic_name",
			"statistic_flags_short",
			"statistic_flags_long",
		},
		nil,
	)
	metricDeviceStatus = prometheus.NewDesc(
		"smartctl_device_status",
		"Device status",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceErrorLogCount = prometheus.NewDesc(
		"smartctl_device_error_log_count",
		"Device SMART error log count",
		[]string{
			"device",
			"error_log_type",
		},
		nil,
	)
	metricDeviceSelfTestLogCount = prometheus.NewDesc(
		"smartctl_device_self_test_log_count",
		"Device SMART self test log count",
		[]string{
			"device",
			"self_test_log_type",
		},
		nil,
	)
	metricDeviceSelfTestLogErrorCount = prometheus.NewDesc(
		"smartctl_device_self_test_log_error_count",
		"Device SMART self test log error count",
		[]string{
			"device",
			"self_test_log_type",
		},
		nil,
	)
	metricDeviceERCSeconds = prometheus.NewDesc(
		"smartctl_device_erc_seconds",
		"Device SMART Error Recovery Control Seconds",
		[]string{
			"device",
			"op_type",
		},
		nil,
	)
)

func init() {
	jsonCache.Store("", JSONCache{})
	registerCollector("disksmart", defaultEnabled, NewDiskSmartCollector)
}

func NewDiskSmartCollector(logger log.Logger) (Collector, error) {
	// Scan the host devices
	json := readSMARTctlDevices(logger)
	scanDevices := json.Get("devices").Array()
	scanDevicesSet := make(map[string]bool)
	var scanDeviceNames []diskDevice
	for _, d := range scanDevices {
		deviceName := d.Get("name").String()
		deviceType := d.Get("type").String()
		fullDeviceName := fmt.Sprintf("%s -d %s", deviceName, deviceType)
		level.Info(logger).Log("msg", "Found device", "name", fullDeviceName)
		scanDevicesSet[deviceName] = true
		scanDeviceNames = append(scanDeviceNames, diskDevice{name: deviceName, deviceType: deviceType})
	}

	if len(scanDeviceNames) == 0 {
		level.Error(logger).Log("msg", "No devices found")
	}

	return &smartCollector{
		smartctlVersion:         metricSmartctlVersion,
		smartctlDevice:          metricDeviceModel,
		attribute:               metricDeviceAttribute,
		temperature:             metricDeviceTemperature,
		percentageUsed:          metricDevicePercentageUsed,
		availableSpare:          metricDeviceAvailableSpare,
		availableSpareThreshold: metricDeviceAvailableSpareThreshold,
		criticalWarning:         metricDeviceCriticalWarning,
		mediaErrors:             metricDeviceMediaErrors,
		numErrLogEntries:        metricDeviceNumErrLogEntries,
		bytesRead:               metricDeviceBytesRead,
		bytesWritten:            metricDeviceBytesWritten,
		smartStatus:             metricDeviceSmartStatus,
		smartctlExitStatus:      metricDeviceExitStatus,
		state:                   metricDeviceState,
		statistics:              metricDeviceStatistics,
		status:                  metricDeviceStatus,
		errorLogCount:           metricDeviceErrorLogCount,
		selfTestLogCount:        metricDeviceSelfTestLogCount,
		selfTestLogErrorCount:   metricDeviceSelfTestLogErrorCount,
		ercSeconds:              metricDeviceERCSeconds,
		devices:                 scanDeviceNames,
		logger:                  logger,
	}, nil
}

func (c *smartCollector) Update(ch chan<- prometheus.Metric) error {
	info := NewSMARTctlInfo(ch)
	for _, device := range c.devices {
		json := readData(c.logger, device.name, device.deviceType)
		if json.Exists() {
			info.SetJSON(json)
			smart := NewSMARTctl(c.logger, json, ch)
			smart.Collect()
		}
	}
	info.Collect()

	return nil
}

func readSMARTctlDevices(logger log.Logger) gjson.Result {
	level.Debug(logger).Log("msg", "Scanning for devices")
	out, err := exec.Command(*smartctlPath, "--json", "--scan").Output()
	if exiterr, ok := err.(*exec.ExitError); ok {
		level.Debug(logger).Log("msg", "Exit Status", "exit_code", exiterr.ExitCode())
		// The smartctl command returns 2 if devices are sleeping, ignore this error.
		if exiterr.ExitCode() != 2 {
			level.Warn(logger).Log("msg", "S.M.A.R.T. output reading error", "err", err)
			return gjson.Result{}
		}
	}
	return parseJSON(string(out))
}

// NewSMARTctlInfo is smartctl constructor
func NewSMARTctlInfo(ch chan<- prometheus.Metric) SMARTctlInfo {
	smart := SMARTctlInfo{}
	smart.ch = ch
	smart.Ready = false
	return smart
}

// SetJSON metrics
func (smart *SMARTctlInfo) SetJSON(json gjson.Result) {
	if !smart.Ready {
		smart.json = json
		smart.Ready = true
	}
}

// Collect metrics
func (smart *SMARTctlInfo) Collect() {
	if smart.Ready {
		smart.mineVersion()
	}
}

func (smart *SMARTctlInfo) mineVersion() {
	smartctlJSON := smart.json.Get("smartctl")
	smartctlVersion := smartctlJSON.Get("version").Array()
	jsonVersion := smart.json.Get("json_format_version").Array()
	smart.ch <- prometheus.MustNewConstMetric(
		metricSmartctlVersion,
		prometheus.GaugeValue,
		1,
		fmt.Sprintf("%d.%d", jsonVersion[0].Int(), jsonVersion[1].Int()),
		fmt.Sprintf("%d.%d", smartctlVersion[0].Int(), smartctlVersion[1].Int()),
		smartctlJSON.Get("svn_revision").String(),
		smartctlJSON.Get("build_info").String(),
	)
}

// NewSMARTctl is smartctl constructor
func NewSMARTctl(logger log.Logger, json gjson.Result, ch chan<- prometheus.Metric) SMARTctl {
	return SMARTctl{
		ch:     ch,
		json:   json,
		logger: logger,
		device: SMARTDevice{
			device: strings.TrimPrefix(strings.TrimSpace(json.Get("device.name").String()), "/dev/"),
			serial: strings.TrimSpace(json.Get("serial_number").String()),
			family: strings.TrimSpace(json.Get("model_family").String()),
			model:  strings.TrimSpace(json.Get("model_name").String()),
		},
	}
}

// Parse json to gjson object
func parseJSON(data string) gjson.Result {
	if !gjson.Valid(data) {
		return gjson.Parse("{}")
	}
	return gjson.Parse(data)
}

// GetStringIfExists returns json value or default
func GetStringIfExists(json gjson.Result, key string, def string) string {
	value := json.Get(key)
	if value.Exists() {
		return value.String()
	}
	return def
}

// GetFloatIfExists returns json value or default
func GetFloatIfExists(json gjson.Result, key string, def float64) float64 {
	value := json.Get(key)
	if value.Exists() {
		return value.Float()
	}
	return def
}

// Select json source and parse
func readData(logger log.Logger, device string, deviceType string) gjson.Result {

	cacheValue, cacheOk := jsonCache.Load(device)
	if !cacheOk || time.Now().After(cacheValue.(JSONCache).LastCollect.Add(*smartctlInterval)) {
		json, ok := readSMARTctl(logger, device, deviceType)
		if ok {
			jsonCache.Store(device, JSONCache{JSON: json, LastCollect: time.Now()})
			j, found := jsonCache.Load(device)
			if !found {
				level.Warn(logger).Log("msg", "device not found", "device", device)
			}
			return j.(JSONCache).JSON
		}
		return gjson.Result{}
	}
	return cacheValue.(JSONCache).JSON
}

// Get json from smartctl and parse it
func readSMARTctl(logger log.Logger, device string, deviceType string) (gjson.Result, bool) {
	out, err := exec.Command(*smartctlPath, "--json", "--info", "--health", "--attributes", "--tolerance=verypermissive", "--nocheck=standby", "--format=brief", device, "-d", deviceType).Output()
	if err != nil {
		level.Warn(logger).Log("msg", "S.M.A.R.T. output reading", "err", err)
	}
	json := parseJSON(string(out))
	rcOk := resultCodeIsOk(logger, json.Get("smartctl.exit_status").Int())
	jsonOk := jsonIsOk(logger, json)
	return json, rcOk && jsonOk
}

// Parse smartctl return code
func resultCodeIsOk(logger log.Logger, SMARTCtlResult int64) bool {
	result := true
	if SMARTCtlResult > 0 {
		b := SMARTCtlResult
		if (b & 1) != 0 {
			level.Error(logger).Log("msg", "Command line did not parse.")
			result = false
		}
		if (b & (1 << 1)) != 0 {
			level.Error(logger).Log("msg", "Device open failed, device did not return an IDENTIFY DEVICE structure, or device is in a low-power mode")
			result = false
		}
		if (b & (1 << 2)) != 0 {
			level.Warn(logger).Log("msg", "Some SMART or other ATA command to the disk failed, or there was a checksum error in a SMART data structure")
		}
		if (b & (1 << 3)) != 0 {
			level.Warn(logger).Log("msg", "SMART status check returned 'DISK FAILING'.")
		}
		if (b & (1 << 4)) != 0 {
			level.Warn(logger).Log("msg", "We found prefail Attributes <= threshold.")
		}
		if (b & (1 << 5)) != 0 {
			level.Warn(logger).Log("msg", "SMART status check returned 'DISK OK' but we found that some (usage or prefail) Attributes have been <= threshold at some time in the past.")
		}
		if (b & (1 << 6)) != 0 {
			level.Warn(logger).Log("msg", "The device error log contains records of errors.")
		}
		if (b & (1 << 7)) != 0 {
			level.Warn(logger).Log("msg", "The device self-test log contains records of errors. [ATA only] Failed self-tests outdated by a newer successful extended self-test are ignored.")
		}
	}
	return result
}

// Check json
func jsonIsOk(logger log.Logger, json gjson.Result) bool {
	messages := json.Get("smartctl.messages")
	if messages.Exists() {
		for _, message := range messages.Array() {
			if message.Get("severity").String() == "error" {
				level.Error(logger).Log("msg", message.Get("string").String())
				return false
			}
		}
	}
	return true
}

// Collect metrics
func (smart *SMARTctl) Collect() {
	smart.mineExitStatus()
	smart.mineDevice()
	smart.mineDeviceAttribute()
	smart.mineTemperatures()
	smart.mineDeviceSCTStatus()
	smart.mineDeviceStatistics()
	smart.mineDeviceStatus()
	smart.mineDeviceErrorLog()
	smart.mineDeviceSelfTestLog()
	smart.mineDeviceERC()
	smart.minePercentageUsed()
	smart.mineAvailableSpare()
	smart.mineAvailableSpareThreshold()
	smart.mineCriticalWarning()
	smart.mineMediaErrors()
	smart.mineNumErrLogEntries()
	smart.mineBytesRead()
	smart.mineBytesWritten()
	smart.mineSmartStatus()

}
func (smart *SMARTctl) mineExitStatus() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceExitStatus,
		prometheus.GaugeValue,
		smart.json.Get("smartctl.exit_status").Float(),
		smart.device.device,
	)
}

func (smart *SMARTctl) mineDevice() {
	device := smart.json.Get("device")
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceModel,
		prometheus.GaugeValue,
		1,
		smart.device.device,
		device.Get("type").String(),
		device.Get("protocol").String(),
		smart.device.family,
		smart.device.model,
		smart.device.serial,
		GetStringIfExists(smart.json, "ata_additional_product_id", "unknown"),
		smart.json.Get("firmware_version").String(),
		smart.json.Get("ata_version.string").String(),
		smart.json.Get("sata_version.string").String(),
		smart.json.Get("form_factor.name").String(),
	)
}

func (smart *SMARTctl) mineDeviceAttribute() {
	for _, attribute := range smart.json.Get("ata_smart_attributes.table").Array() {
		name := strings.TrimSpace(attribute.Get("name").String())
		flagsShort := strings.TrimSpace(attribute.Get("flags.string").String())
		flagsLong := smart.mineLongFlags(attribute.Get("flags"), []string{
			"prefailure",
			"updated_online",
			"performance",
			"error_rate",
			"event_count",
			"auto_keep",
		})
		id := attribute.Get("id").String()
		for key, path := range map[string]string{
			"value":  "value",
			"worst":  "worst",
			"thresh": "thresh",
			"raw":    "raw.value",
		} {
			smart.ch <- prometheus.MustNewConstMetric(
				metricDeviceAttribute,
				prometheus.GaugeValue,
				attribute.Get(path).Float(),
				smart.device.device,
				name,
				flagsShort,
				flagsLong,
				key,
				id,
			)
		}
	}
}

func (smart *SMARTctl) mineTemperatures() {
	temperatures := smart.json.Get("temperature")
	if temperatures.Exists() {
		temperatures.ForEach(func(key, value gjson.Result) bool {
			smart.ch <- prometheus.MustNewConstMetric(
				metricDeviceTemperature,
				prometheus.GaugeValue,
				value.Float(),
				smart.device.device,
				key.String(),
			)
			return true
		})
	}
}

func (smart *SMARTctl) mineDeviceSCTStatus() {
	status := smart.json.Get("ata_sct_status")
	if status.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceState,
			prometheus.GaugeValue,
			status.Get("device_state").Float(),
			smart.device.device,
		)
	}
}

func (smart *SMARTctl) minePercentageUsed() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDevicePercentageUsed,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.percentage_used").Float(),
		smart.device.device,
	)
}

func (smart *SMARTctl) mineAvailableSpare() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceAvailableSpare,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.available_spare").Float(),
		smart.device.device,
	)
}

func (smart *SMARTctl) mineAvailableSpareThreshold() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceAvailableSpareThreshold,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.available_spare_threshold").Float(),
		smart.device.device,
	)
}

func (smart *SMARTctl) mineCriticalWarning() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceCriticalWarning,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.critical_warning").Float(),
		smart.device.device,
	)
}

func (smart *SMARTctl) mineMediaErrors() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceMediaErrors,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.media_errors").Float(),
		smart.device.device,
	)
}

func (smart *SMARTctl) mineNumErrLogEntries() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceNumErrLogEntries,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.num_err_log_entries").Float(),
		smart.device.device,
	)
}

func (smart *SMARTctl) mineBytesRead() {
	blockSize := smart.json.Get("logical_block_size").Float() * 1024
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceBytesRead,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.data_units_read").Float()*blockSize,
		smart.device.device,
	)
}

func (smart *SMARTctl) mineBytesWritten() {
	blockSize := smart.json.Get("logical_block_size").Float() * 1024
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceBytesWritten,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.data_units_written").Float()*blockSize,
		smart.device.device,
	)
}

func (smart *SMARTctl) mineSmartStatus() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceSmartStatus,
		prometheus.GaugeValue,
		smart.json.Get("smart_status.passed").Float(),
		smart.device.device,
	)
}

func (smart *SMARTctl) mineDeviceStatistics() {
	for _, page := range smart.json.Get("ata_device_statistics.pages").Array() {
		table := strings.TrimSpace(page.Get("name").String())
		// skip vendor-specific statistics (they lead to duplicate metric labels on Seagate Exos drives,
		// see https://github.com/Sheridan/smartctl_exporter/issues/3 for details)
		if table == "Vendor Specific Statistics" {
			continue
		}
		for _, statistic := range page.Get("table").Array() {
			smart.ch <- prometheus.MustNewConstMetric(
				metricDeviceStatistics,
				prometheus.GaugeValue,
				statistic.Get("value").Float(),
				smart.device.device,
				smart.device.family,
				smart.device.model,
				smart.device.serial,
				table,
				strings.TrimSpace(statistic.Get("name").String()),
				strings.TrimSpace(statistic.Get("flags.string").String()),
				smart.mineLongFlags(statistic.Get("flags"), []string{
					"valid",
					"normalized",
					"supports_dsn",
					"monitored_condition_met",
				}),
			)
		}
	}

	for _, statistic := range smart.json.Get("sata_phy_event_counters.table").Array() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceStatistics,
			prometheus.GaugeValue,
			statistic.Get("value").Float(),
			smart.device.device,
			"SATA PHY Event Counters",
			strings.TrimSpace(statistic.Get("name").String()),
			"V---",
			"valid",
		)
	}
}

func (smart *SMARTctl) mineLongFlags(json gjson.Result, flags []string) string {
	var result []string
	for _, flag := range flags {
		jFlag := json.Get(flag)
		if jFlag.Exists() && jFlag.Bool() {
			result = append(result, flag)
		}
	}
	return strings.Join(result, ",")
}

func (smart *SMARTctl) mineDeviceStatus() {
	status := smart.json.Get("smart_status")
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceStatus,
		prometheus.GaugeValue,
		status.Get("passed").Float(),
		smart.device.device,
	)
}

func (smart *SMARTctl) mineDeviceErrorLog() {
	for logType, status := range smart.json.Get("ata_smart_error_log").Map() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceErrorLogCount,
			prometheus.GaugeValue,
			status.Get("count").Float(),
			smart.device.device,
			logType,
		)
	}
}

func (smart *SMARTctl) mineDeviceSelfTestLog() {
	for logType, status := range smart.json.Get("ata_smart_self_test_log").Map() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceSelfTestLogCount,
			prometheus.GaugeValue,
			status.Get("count").Float(),
			smart.device.device,
			logType,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceSelfTestLogErrorCount,
			prometheus.GaugeValue,
			status.Get("error_count_total").Float(),
			smart.device.device,
			logType,
		)
	}
}

func (smart *SMARTctl) mineDeviceERC() {
	for ercType, status := range smart.json.Get("ata_sct_erc").Map() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceERCSeconds,
			prometheus.GaugeValue,
			status.Get("deciseconds").Float()/10.0,
			smart.device.device,
			ercType,
		)
	}
}
