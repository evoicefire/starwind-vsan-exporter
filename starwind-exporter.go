package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v3"
)

const (
	namespace = "starwind"
)

type metricInfo struct {
	Desc       *prometheus.Desc
	Type       prometheus.ValueType
	Lookup     string
	LabelValue bool
}

var (
	deviceLabelNames = []string{"device_index"}
	haNodeLabelNames = []string{"device_index", "node_index"}
)

func newMetric(metricName string, docString string, t prometheus.ValueType, constLabels prometheus.Labels, variableLabels []string, lookup string, labelvalue bool) metricInfo {
	return metricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", metricName),
			docString,
			append(deviceLabelNames, variableLabels...),
			constLabels,
		),
		Type:       t,
		Lookup:     lookup,
		LabelValue: labelvalue,
	}
}

func newHAMetric(metricName string, docString string, t prometheus.ValueType, constLabels prometheus.Labels, variableLabels []string, lookup string, labelvalue bool) metricInfo {
	return metricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", metricName),
			docString,
			append(haNodeLabelNames, variableLabels...),
			constLabels,
		),
		Type:       t,
		Lookup:     lookup,
		LabelValue: labelvalue,
	}
}

type metrics map[int]metricInfo

var (
	deviceMetrics = metrics{
		1:  newMetric("name", "Name of the starwind device", prometheus.CounterValue, nil, []string{"device_name"}, "DeviceName", true),
		2:  newMetric("id", "ID of the starwind device", prometheus.CounterValue, nil, []string{"device_id"}, "DeviceId", true),
		3:  newMetric("header_path", "Header path of the starwind device", prometheus.CounterValue, nil, []string{"header_path"}, "DeviceHeaderPath", true),
		4:  newMetric("type", "Header path of the starwind device", prometheus.CounterValue, nil, []string{"device_type"}, "DeviceType", true),
		5:  newMetric("bus_type", "Bus type of the starwind device", prometheus.CounterValue, nil, []string{"bus_type"}, "DeviceBusType", true),
		6:  newMetric("serial_id", "Serial id of the starwind device", prometheus.CounterValue, nil, []string{"serial_id"}, "SerialId", true),
		7:  newMetric("eui_64_id", "EUI64 id of the starwind device", prometheus.CounterValue, nil, []string{"eui_64_id"}, "Eui64Id", true),
		8:  newMetric("naa_64_id", "NAA64 id of the starwind device", prometheus.CounterValue, nil, []string{"naa_64_id"}, "Naa64Id", true),
		9:  newMetric("scsi_inquiry", "SCSI Inquiry of the starwind device", prometheus.CounterValue, nil, []string{"scsi_inquiry"}, "DeviceId", true),
		10: newMetric("mounted", "Whether the device is mounted or not. 1 is true 0 is false", prometheus.GaugeValue, nil, nil, "DeviceMounted", false),
		11: newMetric("parent", "Device name of the parent device if it exists", prometheus.CounterValue, nil, []string{"parent"}, "parent", true),
		12: newMetric("other_state", "Device other state. Unknown value meaning", prometheus.GaugeValue, nil, nil, "state", false),
		13: newMetric("reservation", "Device reservation. Unknown meaning. 1 is yes and 0 is no", prometheus.GaugeValue, nil, nil, "reservation", false),
		14: newMetric("numa_node", "Device numa node", prometheus.CounterValue, nil, []string{"numa_node"}, "DeviceNumaNode", true),
		15: newMetric("header", "Device header", prometheus.GaugeValue, nil, []string{"header"}, "header", true),
		16: newMetric("file", "Device file location", prometheus.CounterValue, nil, []string{"file"}, "file", true),
		17: newMetric("buffering", "Device buffering status. 1 is yes and 0 is no", prometheus.GaugeValue, nil, nil, "buffering", false),
		18: newMetric("asyncmode", "Device asyncmode 1 is yes and 0 is no", prometheus.GaugeValue, nil, nil, "asyncmode", false),
		19: newMetric("sectorsize", "Device sectorsize in bytes", prometheus.GaugeValue, nil, nil, "SectorSize", false),
		20: newMetric("physical_sector_size", "Device physical sector size in bytes", prometheus.GaugeValue, nil, nil, "PhySectorSize", false),
		21: newMetric("image_size_low", "Device image size low. Unknown purpose.", prometheus.GaugeValue, nil, nil, "ImageSizeLow", false),
		22: newMetric("image_size_high", "Device image size high. Unknown purpose.", prometheus.GaugeValue, nil, nil, "ImageSizeHigh", false),
		23: newMetric("readonly", "Device readonly status. 0 is no and 1 is yes", prometheus.GaugeValue, nil, nil, "readonly", false),
		24: newMetric("state", "Device state. 1 is probably good and 0 is probably bad", prometheus.GaugeValue, nil, nil, "DeviceState", false),
		25: newMetric("cachemode", "Device cachemode", prometheus.CounterValue, nil, []string{"cachemode"}, "CacheMode", true),
		26: newMetric("scsi_lun", "Device scsi lun. Unknown values", prometheus.GaugeValue, nil, []string{"scsi_lun"}, "ScsiLun", true),
	}

	haMetrics = metrics{
		1:  newMetric("ha_serialid_string", "", prometheus.CounterValue, nil, []string{"ha_serialid_string"}, "ha_serialid_string", true),
		2:  newMetric("ha_synch_status", "", prometheus.GaugeValue, nil, nil, "ha_synch_status", false),
		3:  newMetric("ha_synch_percent", "", prometheus.GaugeValue, nil, nil, "ha_synch_percent", false),
		4:  newMetric("ha_synch_type", "", prometheus.GaugeValue, nil, nil, "ha_synch_type", false),
		5:  newMetric("ha_sync_elapsed_time", "", prometheus.GaugeValue, nil, nil, "ha_sync_elapsed_time", false),
		6:  newMetric("ha_sync_estimated_time", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		7:  newMetric("ha_priority", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		8:  newMetric("ha_is_node_removed_from_partners", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		9:  newMetric("ha_is_storage_extend_supported", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		10: newMetric("ha_is_storage_snapshot_supported", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		11: newMetric("ha_is_storage_device_ready", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		12: newMetric("ha_is_storage_device_readonly", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		13: newMetric("ha_is_SMISHidden", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		14: newMetric("ha_autosynch_enabled", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		15: newMetric("ha_wait_on_autosynch", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		16: newMetric("ha_auto_sync_priority", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		17: newMetric("ha_maintenance_mode", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		18: newMetric("ha_sync_traffic_share", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		19: newMetric("ha_alua_group_node_state", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		20: newMetric("ha_tracker", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		21: newMetric("ha_tracker_frozen", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		22: newMetric("ha_tracker_snapshots_storage", "", prometheus.CounterValue, nil, []string{"ha_tracker_snapshots_storage"}, "ha_serialid_string", true),
		23: newMetric("ha_tracker_mount_time", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		24: newMetric("ha_tracker_mount_snapshot", "", prometheus.CounterValue, nil, []string{"ha_tracker_mount_snapshot"}, "ha_serialid_string", true),
		25: newMetric("ha_tracker_status", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		26: newMetric("ha_tracker_pending", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		27: newMetric("ha_tracker_replicated", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		28: newMetric("ha_tracker_replicating", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		29: newMetric("ha_tracker_scheduled", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		30: newMetric("ha_node_type", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		31: newMetric("ha_partner_nodes_count", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false), // this one is important
		32: newMetric("ha_failover_config_type", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
		33: newMetric("ha_sis_status", "", prometheus.GaugeValue, nil, nil, "ha_serialid_string", false),
	}

	haPartnerMetrics = metrics{
		34: newHAMetric("ha_partner_node_host_name", "", prometheus.CounterValue, nil, []string{"ha_partner_node_host_name"}, "ha_partner_node_host_name", true),
		35: newHAMetric("ha_partner_node_target_name", "", prometheus.CounterValue, nil, []string{"ha_partner_node_target_name"}, "ha_partner_node_target_name", true),
		36: newHAMetric("ha_partner_node_priority", "", prometheus.GaugeValue, nil, nil, "ha_partner_node_priority", false),
		37: newHAMetric("ha_partner_node_type", "", prometheus.GaugeValue, nil, nil, "ha_partner_node_type", false),
		38: newHAMetric("ha_partner_node_storage_device_type", "", prometheus.CounterValue, nil, []string{"ha_partner_node_storage_device_type"}, "ha_partner_node_storage_device_type", true),
		39: newHAMetric("ha_partner_node_sync_channels", "", prometheus.CounterValue, nil, []string{"ha_partner_node_sync_channels"}, "ha_partner_node_sync_channels", true),
		40: newHAMetric("ha_partner_node_heartbeat_channels", "", prometheus.CounterValue, nil, []string{"ha_partner_node_heartbeat_channels"}, "ha_partner_node_heartbeat_channels", true),
		41: newHAMetric("ha_partner_node_is_exist_sync_valid_connection", "", prometheus.CounterValue, nil, []string{"ha_partner_node_is_exist_sync_valid_connection"}, "ha_partner_node_is_exist_sync_valid_connection", true),
		42: newHAMetric("ha_partner_node_is_exist_heartbeat_valid_connection", "", prometheus.CounterValue, nil, []string{"ha_partner_node_is_exist_heartbeat_valid_connection"}, "ha_partner_node_is_exist_heartbeat_valid_connection", true),
		43: newHAMetric("ha_partner_node_sync_status", "", prometheus.GaugeValue, nil, nil, "ha_partner_node_sync_status", false),
		44: newHAMetric("ha_partner_node_sync_percent", "", prometheus.GaugeValue, nil, nil, "ha_partner_node_sync_percent", false),
		45: newHAMetric("ha_partner_node_sync_type", "", prometheus.GaugeValue, nil, nil, "ha_partner_node_sync_type", false),
		46: newHAMetric("ha_partner_node_sync_elapsed_time", "", prometheus.GaugeValue, nil, nil, "ha_partner_node_sync_elapsed_time", false),
		47: newHAMetric("ha_partner_node_sync_estimated_time", "", prometheus.GaugeValue, nil, nil, "ha_partner_node_sync_estimated_time", false),
		48: newHAMetric("ha_partner_node_tracker_frozen", "", prometheus.GaugeValue, nil, nil, "ha_partner_node_tracker_frozen", false),
		49: newHAMetric("ha_partner_node_tracker_snapshots_storage", "", prometheus.GaugeValue, nil, []string{"ha_partner_node_tracker_snapshots_storage"}, "ha_partner_node_tracker_snapshots_storage", true),
		50: newHAMetric("ha_partner_node_tracker_mount_time", "", prometheus.GaugeValue, nil, nil, "ha_partner_node_tracker_mount_time", false),
		51: newHAMetric("ha_partner_node_tracker_mount_snapshot", "", prometheus.GaugeValue, nil, []string{"ha_partner_node_tracker_mount_snapshot"}, "ha_partner_node_tracker_mount_snapshot", true),
		52: newHAMetric("ha_partner_node_maintenance_mode", "", prometheus.GaugeValue, nil, nil, "ha_partner_node_maintenance_mode", false),
		53: newHAMetric("ha_partner_node_alua_group_node_state", "", prometheus.GaugeValue, nil, nil, "ha_partner_node_alua_group_node_state", false),
	}

	starwindInfo = prometheus.NewDesc(prometheus.BuildFQName(namespace, "version", "info"), "Starwind version info.", []string{"release_date", "version"}, nil)
	starwindUp   = prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "up"), "Was the last scrape of Starwind successful.", nil, nil)
)

type Exporter struct {
	URI          string
	mutex        sync.RWMutex
	fetchStat    func() (*Devices, error)
	up           prometheus.Gauge
	totalScrapes prometheus.Counter
	allMetrics   map[int]metricInfo
	logger       log.Logger
}

type Config struct {
	Servers []*Server `yaml:"servers"`
}

type Server struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Host     string `yaml:"host"`
	Registry *prometheus.Registry
}

func NewConfig() *Config {
	return &Config{
		Servers: []*Server{
			{
				Username: "root",
				Password: "starwind",
				Host:     "localhost:3261",
				Registry: prometheus.NewRegistry(),
			},
		},
	}
}

func (s *Server) NewExporter(timeout time.Duration, logger log.Logger) (*Exporter, error) {
	var fetchStat func() (*Devices, error)
	fetchStat, _ = fetchTCP(s.Host, timeout, s)

	return &Exporter{
		URI:       s.Host,
		fetchStat: fetchStat,
		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "up",
			Help:      "Was the last scrape of Starwind successful.",
		}),
		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "exporter_scrapes_total",
			Help:      "Current total Starwind scrapes.",
		}),
		logger: logger,
	}, nil

}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range deviceMetrics {
		ch <- m.Desc
	}

	ch <- starwindInfo
	ch <- starwindUp
	ch <- e.totalScrapes.Desc()
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	up := e.scrape(ch)

	ch <- prometheus.MustNewConstMetric(starwindUp, prometheus.GaugeValue, up)
	ch <- e.totalScrapes
}

func (e *Exporter) scrape(ch chan<- prometheus.Metric) (up float64) {

	level.Info(e.logger).Log("msg", fmt.Sprintf("Starting scrape of %s now", e.URI))
	e.totalScrapes.Inc()
	var err error

	devices, err := e.fetchStat()
	if err != nil {
		level.Error(e.logger).Log("msg", "Can't scrape starwind", "err", err)
		return 0
	}
	e.parseMetrics(deviceMetrics, devices, ch)
	e.parseMetrics(haMetrics, devices, ch)
	e.parseHAMetrics(haPartnerMetrics, devices, ch)
	return 1

}

func (e *Exporter) parseMetrics(metrics map[int]metricInfo, devices *Devices, ch chan<- prometheus.Metric) {
	for _, device := range *devices {
		for _, metric := range metrics {
			c := device.Stats[metric.Lookup]
			if len(c) == 0 {
				// this metric isn't present for this device so skip
				continue
			}
			valueString := c[0]

			if metric.LabelValue {
				// value is a label
				ch <- prometheus.MustNewConstMetric(metric.Desc, metric.Type, 1, strconv.Itoa(device.Id), valueString)
			} else {
				var value int

				switch valueString {
				case "yes":
					// yes or nooy value
					value = 1
				case "no":
					value = 0
				default:
					v, err := strconv.Atoi(valueString)
					if err != nil {
						value = 0
					}
					value = v
				}
				ch <- prometheus.MustNewConstMetric(metric.Desc, metric.Type, float64(value), strconv.Itoa(device.Id))
			}
		}
	}

}

func (e *Exporter) parseHAMetrics(metrics map[int]metricInfo, devices *Devices, ch chan<- prometheus.Metric) {
	for _, device := range *devices {
		// Check if device is a HA device
		if device.Stats["DeviceType"][0] != "HA Image" {
			// skip device if not HA
			continue
		}
		// get number of nodes for partner stats
		numNodes, err := strconv.Atoi(device.Stats["ha_partner_nodes_count"][0])
		if err != nil {
			continue
		}

		level.Info(e.logger).Log("msg", fmt.Sprintf("%d HA nodes found", numNodes))

		for _, metric := range metrics {
			// parse metric lookup and replace node with nodindex
			for i := 1; i < numNodes+1; i++ {
				e := strings.Replace(metric.Lookup, "node", fmt.Sprintf("node%d", i), 1)
				c := device.Stats[e]
				if len(c) == 0 {
					// this metric isn't present for this device so skip
					continue
				}
				valueString := c[0]

				if metric.LabelValue {
					// value is a label
					ch <- prometheus.MustNewConstMetric(metric.Desc, metric.Type, 1, strconv.Itoa(device.Id), strconv.Itoa(i), valueString)
				} else {
					var value int

					switch valueString {
					case "yes":
						// yes or nooy value
						value = 1
					case "no":
						value = 0
					default:
						v, err := strconv.Atoi(valueString)
						if err != nil {
							value = 0
						}
						value = v
					}
					ch <- prometheus.MustNewConstMetric(metric.Desc, metric.Type, float64(value), strconv.Itoa(device.Id), strconv.Itoa(i))
				}
			}

		}
	}
}

func fetchTCP(uri string, timeout time.Duration, server *Server) (func() (*Devices, error), error) {
	return func() (*Devices, error) {
		conn, err := dialTCP(uri, timeout)
		if err != nil {
			return nil, err
		}
		defer conn.Close()

		scanner := bufio.NewScanner(conn)

		// Send protocolversion 100
		if _, err := fmt.Fprintf(conn, "%s\n", "protocolversion 100"); err != nil {
			return nil, err
		}
		if err := checkSuccess(scanner); err != nil {
			return nil, fmt.Errorf("Error setting protocol version")
		}

		// Login
		if _, err := fmt.Fprintf(conn, "%s %s %s\n", "login", server.Username, server.Password); err != nil {
			return nil, err
		}
		if err := checkSuccess(scanner); err != nil {
			return nil, fmt.Errorf("Error authenticating")
		}

		// Get all metrics
		if _, err := fmt.Fprintf(conn, "%s\n", "list"); err != nil {
			return nil, err
		}
		if err := checkSuccess(scanner); err != nil {
			return nil, fmt.Errorf("Error getting metrics")
		}

		var id int
		var device Device
		var devices Devices
		var seen bool
		for scanner.Scan() {
			parsed := strings.Split(string(scanner.Bytes()), "=")
			if parsed[0] == "DeviceName" {
				// We have a new device so append current device to devices
				if seen {
					d := device
					devices = append(devices, &d)
					// increment id
					id += 1
				}
				// set device to new device with new id
				device = Device{Id: id, Stats: make(map[string][]string)}
			} else if !seen {
				// skip loop as this is just preamble
				continue
			}

			if parsed[0] == "" && seen {
				// we are done so break
				d := device
				devices = append(devices, &d)
				break
			}

			device.Stats[parsed[0]] = append(device.Stats[parsed[0]], strings.Trim(parsed[1], "\""))
			// mark seen as true as we have just started processing stats
			seen = true
		}

		return &devices, nil
	}, nil
}

type Device struct {
	Id    int
	Stats map[string][]string
}

type Devices []*Device

func checkSuccess(scanner *bufio.Scanner) error {
	success_regex := regexp.MustCompile("200 Completed")
	timer := time.NewTimer(60 * time.Second)
	for {
		if ok := scanner.Scan(); !ok {
			break
		}

		match := success_regex.FindSubmatch(scanner.Bytes())
		if match != nil {
			return nil
		}

		select {
		case <-timer.C:
			return fmt.Errorf("Timeout waiting for success")
		default:
		}
	}
	return fmt.Errorf("Error confirming success")
}

func dialTCP(uri string, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	dialer := &net.Dialer{}
	targetAddress, port, err := net.SplitHostPort(uri)
	if err != nil {
		return nil, err
	}

	ip, err := lookup(targetAddress)
	if err != nil {
		return nil, err
	}

	if ip.IP.To4() == nil {
		return nil, fmt.Errorf("Error resolving IP to ipv4")
	}

	dialTarget := net.JoinHostPort(ip.String(), port)
	dialer.Deadline = deadline

	conn, err := dialer.Dial("tcp", dialTarget)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(deadline)
	conn.SetReadDeadline(deadline)
	return conn, nil
}

func lookup(uri string) (*net.IPAddr, error) {
	var c net.IP
	c = net.ParseIP(uri)
	if c != nil {
		return &net.IPAddr{IP: c}, nil
	}

	ips, err := net.LookupHost(uri)
	if err != nil {
		return nil, err
	}

	c = net.ParseIP(ips[0])
	if c == nil {
		return nil, fmt.Errorf("Invalid Domain")
	}
	ip := &net.IPAddr{IP: c}
	return ip, nil
}

func handleProbe(w http.ResponseWriter, r *http.Request, c *Config) {
	serverName := r.URL.Query().Get("server")
	if serverName == "" {
		http.Error(w, fmt.Sprintf("Module not defined"), http.StatusBadRequest)
		return
	}

	for _, s := range c.Servers {
		if s.Host == serverName {
			handler := promhttp.HandlerFor(s.Registry, promhttp.HandlerOpts{})
			handler.ServeHTTP(w, r)
			return
		}
	}

	http.Error(w, fmt.Sprintf("No module found"), http.StatusBadRequest)
	return
}

func main() {
	var (
		webConfig       = webflag.AddFlags(kingpin.CommandLine)
		listenAddress   = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry. Default 9852").Default(":9852").String()
		metricsPath     = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		probePath       = kingpin.Flag("web.probe-path", "Path under which to expose metrics.").Default("/probe").String()
		starwindTimeout = kingpin.Flag("starwind.timeout", "Timeout for trying to get stats from Starwind.").Default("5s").Duration()
		configFile      = kingpin.Flag("config.file", "TFilepath for configuration.").Default("").String()
	)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("starwind_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("msg", "Starting starwind_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "context", version.BuildContext())

	c := NewConfig()
	if *configFile != "" {
		yamlReader, err := os.Open(*configFile)
		if err != nil {
			level.Error(logger).Log("msg", "Error reading config", "err", err)
			os.Exit(1)
		}
		defer yamlReader.Close()
		decoder := yaml.NewDecoder(yamlReader)
		decoder.KnownFields(true)
		if err = decoder.Decode(c); err != nil {
			level.Error(logger).Log("msg", "Error decoding config", "err", err)
			os.Exit(1)
		}

		for _, server := range c.Servers {
			server.Registry = prometheus.NewRegistry()
		}
	}

	// Create a new exporter for every host in config file
	for _, server := range c.Servers {
		e, err := server.NewExporter(*starwindTimeout, logger)
		if err != nil {
			level.Error(logger).Log("msg", fmt.Sprintf("Error creating an exporter for %s", server.Host), "err", err)
			os.Exit(1)
		}
		server.Registry.MustRegister(e)
		server.Registry.MustRegister(version.NewCollector("starwind_exporter"))
	}

	level.Info(logger).Log("msg", "Listening on address", "address", *listenAddress)

	http.Handle(*metricsPath, promhttp.Handler())
	http.Handle(*probePath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleProbe(w, r, c)
	}))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Starwind Exporter</title></head>
             <body>
             <h1>Starwind Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})
	srv := &http.Server{Addr: *listenAddress}
	if err := web.ListenAndServe(srv, *webConfig, logger); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}
}

type Registries []*prometheus.Registry
